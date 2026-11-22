//! Boot an installed disk the way its bootloader would, without firmware.
//!
//! k7d has no BIOS or UEFI, so GRUB never runs. What GRUB would do on an
//! RHCOS disk is small and fully specified: `blscfg` reads the Boot
//! Loader Specification entries under `/boot/loader/entries/`, picks the
//! highest `version`, and `05_ignition.cfg` substitutes
//! `$ignition_firstboot` from the `/boot/ignition.firstboot` stamp
//! (bootupd's `grub2-static/configs.d`). This module does exactly that
//! on the host — GPT, then the `boot` partition's ext4, read in
//! userspace with `ext4-view`, never mounted — and hands the kernel,
//! initrd and `options` to [`crate::vm::VmBuilder`]. The disk decides
//! what boots: after `rpm-ostree` writes a new deployment the next boot
//! runs *that* kernel, which is what the design note's "per-boot step
//! that lifts `linux`/`initrd`/`options` from the disk" asks for.
//!
//! Not a bootloader: no menu, no GRUB scripting beyond the two
//! snippets above, no `loader.conf` defaults, no `$`-variable other
//! than `$ignition_firstboot` (anything else is an error, not a guess).

use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use ext4_view::{Ext4, Ext4Read};

const SECTOR: u64 = 512;
const GPT_SIGNATURE: &[u8; 8] = b"EFI PART";
/// PARTLABEL coreos-assembler gives the ext4 `/boot` partition.
const BOOT_PARTLABEL: &str = "boot";

#[derive(Debug, thiserror::Error)]
pub enum BlsError {
    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("{disk}: no GPT header at LBA 1 (signature {found:02x?})")]
    NotGpt { disk: PathBuf, found: [u8; 8] },
    #[error("{disk}: GPT partition entries are {size} bytes, expected at least 128")]
    GptEntrySize { disk: PathBuf, size: u32 },
    #[error("{disk}: GPT lists {count} partition entries, refusing more than 1024")]
    GptEntryCount { disk: PathBuf, count: u32 },
    #[error("{disk}: {count} partitions labelled \"boot\", need exactly one")]
    BootPartition { disk: PathBuf, count: usize },
    #[error("{disk}: \"boot\" partition ({first}..={last}) lies past the end of the image")]
    PartitionBounds {
        disk: PathBuf,
        first: u64,
        last: u64,
    },
    #[error("{disk}: boot partition is not ext4: {source}")]
    Ext4 {
        disk: PathBuf,
        #[source]
        source: ext4_view::Ext4Error,
    },
    #[error("{disk}: reading {path} from the boot partition: {source}")]
    BootFile {
        disk: PathBuf,
        path: String,
        #[source]
        source: ext4_view::Ext4Error,
    },
    #[error("{disk}: no BLS entries under /loader/entries")]
    NoEntries { disk: PathBuf },
    #[error("{disk}: BLS entry {entry}: {what}")]
    Entry {
        disk: PathBuf,
        entry: String,
        what: String,
    },
    #[error(
        "{disk}: /ignition.firstboot line {line:?} is not `set ignition_network_kcmdline=...`"
    )]
    Firstboot { disk: PathBuf, line: String },
}

/// One parsed `loader/entries/*.conf`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlsEntry {
    /// File name under `/loader/entries`.
    pub name: String,
    pub title: String,
    pub version: u64,
    /// `linux` path, absolute within the boot partition.
    pub linux: String,
    /// `initrd` path, absolute within the boot partition.
    pub initrd: String,
    /// `options` verbatim, `$ignition_firstboot` not yet substituted.
    pub options: String,
}

impl BlsEntry {
    fn parse(name: &str, text: &str) -> Result<Self, String> {
        let mut title = None;
        let mut version = None;
        let mut linux = None;
        let mut initrd = None;
        let mut options = None;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (key, value) = line
                .split_once(char::is_whitespace)
                .ok_or_else(|| format!("line {line:?} has no value"))?;
            let value = value.trim();
            match key {
                "title" => title = Some(value.to_string()),
                "version" => {
                    version = Some(
                        value
                            .parse::<u64>()
                            .map_err(|e| format!("version {value:?}: {e}"))?,
                    );
                }
                "linux" => linux = Some(value.to_string()),
                "initrd" => {
                    if initrd.is_some() {
                        return Err("more than one initrd line".to_string());
                    }
                    initrd = Some(value.to_string());
                }
                "options" => options = Some(value.to_string()),
                // `grub_users`, `grub_arg`, `grub_class`, `id`, ...:
                // menu cosmetics GRUB ignores for booting too.
                _ => {}
            }
        }
        let need = |what: &str, v: Option<String>| v.ok_or_else(|| format!("no {what} line"));
        let entry = Self {
            name: name.to_string(),
            title: title.unwrap_or_default(),
            version: version.ok_or("no version line")?,
            linux: need("linux", linux)?,
            initrd: need("initrd", initrd)?,
            options: need("options", options)?,
        };
        for (what, p) in [("linux", &entry.linux), ("initrd", &entry.initrd)] {
            if !p.starts_with('/') {
                return Err(format!("{what} path {p:?} is not absolute"));
            }
        }
        Ok(entry)
    }
}

/// What a boot from `disk` runs: the chosen entry's kernel and initrd
/// copied out to host files, and the command line GRUB would have
/// passed.
#[derive(Debug)]
pub struct DiskBoot {
    pub kernel: PathBuf,
    pub initrd: PathBuf,
    pub cmdline: String,
    pub entry: BlsEntry,
    /// `/ignition.firstboot` was present: this boot runs Ignition.
    pub firstboot: bool,
}

impl DiskBoot {
    /// Read `disk`'s bootloader state and extract the kernel and initrd
    /// of the default BLS entry into `out_dir` (created if missing).
    pub fn load(disk: &Path, out_dir: &Path) -> Result<Self, BlsError> {
        let io = |path: &Path, source| BlsError::Io {
            path: path.to_path_buf(),
            source,
        };
        let file = File::open(disk).map_err(|e| io(disk, e))?;
        let image_len = file.metadata().map_err(|e| io(disk, e))?.len();
        let (first, last) = boot_partition(&file, disk, image_len)?;
        let reader = PartitionReader {
            file,
            base: first * SECTOR,
            len: (last - first + 1) * SECTOR,
        };
        let fs = Ext4::load(Box::new(reader)).map_err(|source| BlsError::Ext4 {
            disk: disk.to_path_buf(),
            source,
        })?;
        let boot_file = |path: &str, source| BlsError::BootFile {
            disk: disk.to_path_buf(),
            path: path.to_string(),
            source,
        };
        // `blscfg` boots the entry with the highest `version`; ostree
        // numbers them so the default deployment has it.
        let entry = read_entries(&fs, disk)?
            .into_iter()
            .max_by_key(|e| e.version)
            .ok_or_else(|| BlsError::NoEntries {
                disk: disk.to_path_buf(),
            })?;

        let firstboot_stamp = fs
            .exists("/ignition.firstboot")
            .map_err(|e| boot_file("/ignition.firstboot", e))?;
        let ignition_firstboot = if firstboot_stamp {
            let stamp = fs
                .read_to_string("/ignition.firstboot")
                .map_err(|e| boot_file("/ignition.firstboot", e))?;
            let network =
                firstboot_network_kcmdline(&stamp).map_err(|line| BlsError::Firstboot {
                    disk: disk.to_path_buf(),
                    line,
                })?;
            format!("ignition.firstboot {network}")
        } else {
            String::new()
        };
        let cmdline = entry
            .options
            .replace("${ignition_firstboot}", &ignition_firstboot)
            .replace("$ignition_firstboot", &ignition_firstboot);
        if let Some(at) = cmdline.find('$') {
            return Err(BlsError::Entry {
                disk: disk.to_path_buf(),
                entry: entry.name.clone(),
                what: format!(
                    "options carry a GRUB variable this loader does not know: {:?}",
                    &cmdline[at..]
                ),
            });
        }
        let cmdline = cmdline.split_whitespace().collect::<Vec<_>>().join(" ");

        fs::create_dir_all(out_dir).map_err(|e| io(out_dir, e))?;
        let extract = |guest_path: &str, host_name: &str| -> Result<PathBuf, BlsError> {
            let data = fs.read(guest_path).map_err(|e| boot_file(guest_path, e))?;
            let host = out_dir.join(host_name);
            fs::write(&host, data).map_err(|e| io(&host, e))?;
            Ok(host)
        };
        let kernel = extract(&entry.linux, "vmlinuz")?;
        let initrd = extract(&entry.initrd, "initrd.img")?;
        Ok(Self {
            kernel,
            initrd,
            cmdline,
            entry,
            firstboot: firstboot_stamp,
        })
    }
}

/// Every `/loader/entries/*.conf` on the boot partition, parsed.
fn read_entries(fs: &Ext4, disk: &Path) -> Result<Vec<BlsEntry>, BlsError> {
    let boot_file = |path: &str, source| BlsError::BootFile {
        disk: disk.to_path_buf(),
        path: path.to_string(),
        source,
    };
    let mut entries = Vec::new();
    let dir = fs
        .read_dir("/loader/entries")
        .map_err(|e| boot_file("/loader/entries", e))?;
    for dirent in dir {
        let dirent = dirent.map_err(|e| boot_file("/loader/entries", e))?;
        let name = dirent
            .file_name()
            .as_str()
            .map_err(|e| BlsError::Entry {
                disk: disk.to_path_buf(),
                entry: format!("{:?}", dirent.file_name()),
                what: format!("non-UTF-8 name: {e}"),
            })?
            .to_string();
        if !Path::new(&name)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("conf"))
        {
            continue;
        }
        let path = format!("/loader/entries/{name}");
        let text = fs
            .read_to_string(path.as_str())
            .map_err(|e| boot_file(&path, e))?;
        entries.push(
            BlsEntry::parse(&name, &text).map_err(|what| BlsError::Entry {
                disk: disk.to_path_buf(),
                entry: name.clone(),
                what,
            })?,
        );
    }
    Ok(entries)
}

/// `05_ignition.cfg`: the stamp may `set ignition_network_kcmdline=...`
/// (coreos-installer persists `--append-karg`-less network kargs there);
/// anything else in it is a GRUB script this loader will not run.
fn firstboot_network_kcmdline(stamp: &str) -> Result<String, String> {
    let mut network = String::new();
    for line in stamp.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let value = line
            .strip_prefix("set ignition_network_kcmdline=")
            .ok_or_else(|| line.to_string())?;
        network = value
            .strip_prefix('\'')
            .and_then(|v| v.strip_suffix('\''))
            .or_else(|| value.strip_prefix('"').and_then(|v| v.strip_suffix('"')))
            .unwrap_or(value)
            .to_string();
    }
    Ok(network)
}

/// `(first_lba, last_lba)` of the single partition labelled `boot`.
fn boot_partition(mut file: &File, disk: &Path, image_len: u64) -> Result<(u64, u64), BlsError> {
    let io = |source| BlsError::Io {
        path: disk.to_path_buf(),
        source,
    };
    let mut header = [0u8; 92];
    file.seek(SeekFrom::Start(SECTOR)).map_err(io)?;
    file.read_exact(&mut header).map_err(io)?;
    if &header[..8] != GPT_SIGNATURE {
        let mut found = [0u8; 8];
        found.copy_from_slice(&header[..8]);
        return Err(BlsError::NotGpt {
            disk: disk.to_path_buf(),
            found,
        });
    }
    let u64_at = |b: &[u8], at: usize| {
        let mut a = [0u8; 8];
        a.copy_from_slice(&b[at..at + 8]);
        u64::from_le_bytes(a)
    };
    let u32_at = |b: &[u8], at: usize| {
        let mut a = [0u8; 4];
        a.copy_from_slice(&b[at..at + 4]);
        u32::from_le_bytes(a)
    };
    let entries_lba = u64_at(&header, 72);
    let count = u32_at(&header, 80);
    let entry_size = u32_at(&header, 84);
    if entry_size < 128 {
        return Err(BlsError::GptEntrySize {
            disk: disk.to_path_buf(),
            size: entry_size,
        });
    }
    if count > 1024 {
        return Err(BlsError::GptEntryCount {
            disk: disk.to_path_buf(),
            count,
        });
    }
    let mut table = vec![0u8; count as usize * entry_size as usize];
    file.seek(SeekFrom::Start(entries_lba * SECTOR))
        .map_err(io)?;
    file.read_exact(&mut table).map_err(io)?;
    let mut found = Vec::new();
    for entry in table.chunks_exact(entry_size as usize) {
        if entry[..16].iter().all(|&b| b == 0) {
            continue;
        }
        let name: String = char::decode_utf16(
            entry[56..128]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .take_while(|&c| c != 0),
        )
        .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect();
        if name == BOOT_PARTLABEL {
            found.push((u64_at(entry, 32), u64_at(entry, 40)));
        }
    }
    let &[(first, last)] = found.as_slice() else {
        return Err(BlsError::BootPartition {
            disk: disk.to_path_buf(),
            count: found.len(),
        });
    };
    if first > last || (last + 1) * SECTOR > image_len {
        return Err(BlsError::PartitionBounds {
            disk: disk.to_path_buf(),
            first,
            last,
        });
    }
    Ok((first, last))
}

/// `ext4-view` sees one partition, not the whole disk.
struct PartitionReader {
    file: File,
    base: u64,
    len: u64,
}

impl Ext4Read for PartitionReader {
    fn read(
        &mut self,
        start_byte: u64,
        dst: &mut [u8],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        let end = start_byte
            .checked_add(dst.len() as u64)
            .filter(|&end| end <= self.len)
            .ok_or_else(|| {
                format!(
                    "read of {} bytes at {start_byte:#x} leaves the {:#x}-byte partition",
                    dst.len(),
                    self.len
                )
            })?;
        debug_assert!(end <= self.len);
        self.file.seek(SeekFrom::Start(self.base + start_byte))?;
        self.file.read_exact(dst)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spawner::command;

    const RHCOS_ENTRY: &str = "\
title Red Hat Enterprise Linux CoreOS 9.8.20260715-1 (Plow) (ostree:0)
version 1
options root=UUID=aaaa rw rootflags=prjquota boot=UUID=bbbb ignition.platform.id=metal $ignition_firstboot ostree=/ostree/boot.1/rhcos/5162ed3e/0 console=ttyS0,115200 noapic
linux /ostree/rhcos-5162ed3e/vmlinuz-5.14.0-687.26.1.el9_8.x86_64
initrd /ostree/rhcos-5162ed3e/initramfs-5.14.0-687.26.1.el9_8.x86_64.img
aboot /ostree/rhcos-5162ed3e/aboot.img
abootcfg /ostree/rhcos-5162ed3e/aboot.cfg
";

    #[test]
    fn parses_an_ostree_entry() {
        let e = BlsEntry::parse("ostree-1-rhcos.conf", RHCOS_ENTRY).unwrap();
        assert_eq!(e.version, 1);
        assert!(e.title.starts_with("Red Hat Enterprise Linux CoreOS"));
        assert_eq!(
            e.linux,
            "/ostree/rhcos-5162ed3e/vmlinuz-5.14.0-687.26.1.el9_8.x86_64"
        );
        assert!(e.initrd.ends_with(".img"));
        assert!(e.options.contains("$ignition_firstboot"));
    }

    #[test]
    fn rejects_incomplete_or_relative_entries() {
        for (text, what) in [
            ("title x\nversion 1\nlinux /k\noptions a", "no initrd line"),
            ("title x\nlinux /k\ninitrd /i\noptions a", "no version line"),
            ("version x\nlinux /k\ninitrd /i\noptions a", "version"),
            ("version 1\nlinux k\ninitrd /i\noptions a", "not absolute"),
            (
                "version 1\nlinux /k\ninitrd /i\ninitrd /j\noptions a",
                "more than one initrd",
            ),
        ] {
            let err = BlsEntry::parse("e.conf", text).unwrap_err();
            assert!(err.contains(what), "{text:?}: {err}");
        }
    }

    #[test]
    fn firstboot_stamp_grammar() {
        assert_eq!(firstboot_network_kcmdline("").unwrap(), "");
        assert_eq!(
            firstboot_network_kcmdline(
                "# persisted by coreos-installer\nset ignition_network_kcmdline='ip=dhcp nameserver=1.1.1.1'\n"
            )
            .unwrap(),
            "ip=dhcp nameserver=1.1.1.1"
        );
        assert_eq!(
            firstboot_network_kcmdline("set ignition_network_kcmdline=\"ip=dhcp\"").unwrap(),
            "ip=dhcp"
        );
        assert_eq!(
            firstboot_network_kcmdline("set foo=bar").unwrap_err(),
            "set foo=bar"
        );
    }

    /// A GPT image with an ext4 `boot` partition holding one ostree-style
    /// entry, built with `sgdisk`-free hand-rolled GPT and `mkfs.ext4 -d`
    /// (both in e2fsprogs/util-linux on the node), then loaded the way a
    /// boot would — first with the stamp, then without.
    #[test]
    fn loads_the_default_entry_from_a_gpt_disk() {
        let tmp = tempfile::tempdir().unwrap();
        let tree = tmp.path().join("tree");
        fs::create_dir_all(tree.join("loader.1/entries")).unwrap();
        std::os::unix::fs::symlink("loader.1", tree.join("loader")).unwrap();
        fs::create_dir_all(tree.join("ostree/rhcos-5162ed3e")).unwrap();
        fs::write(
            tree.join("ostree/rhcos-5162ed3e/vmlinuz-5.14.0-687.26.1.el9_8.x86_64"),
            b"KERNEL",
        )
        .unwrap();
        fs::write(
            tree.join("ostree/rhcos-5162ed3e/initramfs-5.14.0-687.26.1.el9_8.x86_64.img"),
            b"INITRD",
        )
        .unwrap();
        fs::write(
            tree.join("loader.1/entries/ostree-1-rhcos.conf"),
            RHCOS_ENTRY,
        )
        .unwrap();
        // An older deployment with a lower version must lose.
        fs::write(
            tree.join("loader.1/entries/ostree-0-rhcos.conf"),
            RHCOS_ENTRY
                .replace("version 1", "version 0")
                .replace("boot.1", "boot.0"),
        )
        .unwrap();
        fs::write(
            tree.join("ignition.firstboot"),
            "set ignition_network_kcmdline='ip=dhcp'\n",
        )
        .unwrap();

        let part = tmp.path().join("boot.ext4");
        File::create(&part).unwrap().set_len(8 << 20).unwrap();
        let out = command("mkfs.ext4")
            .args(["-q", "-F", "-L", "boot", "-d"])
            .arg(&tree)
            .arg(&part)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );

        // GPT: header at LBA 1, 128 entries from LBA 2, partition at LBA 2048.
        let part_bytes = fs::read(&part).unwrap();
        let first_lba = 2048u64;
        let last_lba = first_lba + part_bytes.len() as u64 / SECTOR - 1;
        let mut disk = vec![0u8; ((last_lba + 1) * SECTOR) as usize + 34 * SECTOR as usize];
        let hdr = SECTOR as usize;
        disk[hdr..hdr + 8].copy_from_slice(GPT_SIGNATURE);
        disk[hdr + 72..hdr + 80].copy_from_slice(&2u64.to_le_bytes());
        disk[hdr + 80..hdr + 84].copy_from_slice(&128u32.to_le_bytes());
        disk[hdr + 84..hdr + 88].copy_from_slice(&128u32.to_le_bytes());
        let mut write_entry = |idx: usize, name: &str, first: u64, last: u64| {
            let at = 2 * SECTOR as usize + idx * 128;
            disk[at..at + 16].copy_from_slice(&[0x0f; 16]);
            disk[at + 16..at + 32].copy_from_slice(&[idx as u8 + 1; 16]);
            disk[at + 32..at + 40].copy_from_slice(&first.to_le_bytes());
            disk[at + 40..at + 48].copy_from_slice(&last.to_le_bytes());
            for (i, u) in name.encode_utf16().enumerate() {
                disk[at + 56 + 2 * i..at + 58 + 2 * i].copy_from_slice(&u.to_le_bytes());
            }
        };
        write_entry(0, "BIOS-BOOT", 34, 2047);
        write_entry(1, "boot", first_lba, last_lba);
        let at = (first_lba * SECTOR) as usize;
        disk[at..at + part_bytes.len()].copy_from_slice(&part_bytes);
        let disk_path = tmp.path().join("disk.img");
        fs::write(&disk_path, &disk).unwrap();

        let boot = DiskBoot::load(&disk_path, &tmp.path().join("out")).unwrap();
        assert!(boot.firstboot);
        assert_eq!(boot.entry.name, "ostree-1-rhcos.conf");
        assert_eq!(fs::read(&boot.kernel).unwrap(), b"KERNEL");
        assert_eq!(fs::read(&boot.initrd).unwrap(), b"INITRD");
        assert_eq!(
            boot.cmdline,
            "root=UUID=aaaa rw rootflags=prjquota boot=UUID=bbbb ignition.platform.id=metal \
             ignition.firstboot ip=dhcp ostree=/ostree/boot.1/rhcos/5162ed3e/0 \
             console=ttyS0,115200 noapic"
        );

        // Second boot: the OS removed the stamp.
        let out = command("debugfs")
            .args(["-w", "-R", "rm /ignition.firstboot"])
            .arg(&part)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let part_bytes = fs::read(&part).unwrap();
        disk[at..at + part_bytes.len()].copy_from_slice(&part_bytes);
        fs::write(&disk_path, &disk).unwrap();
        let boot = DiskBoot::load(&disk_path, &tmp.path().join("out2")).unwrap();
        assert!(!boot.firstboot);
        assert!(!boot.cmdline.contains("ignition.firstboot"));
        assert!(!boot.cmdline.contains("  "), "{:?}", boot.cmdline);
        assert!(boot
            .cmdline
            .contains("ostree=/ostree/boot.1/rhcos/5162ed3e/0 console=ttyS0,115200"));

        // Not a GPT disk at all.
        let err = DiskBoot::load(&part, &tmp.path().join("out3")).unwrap_err();
        assert!(matches!(err, BlsError::NotGpt { .. }), "{err}");
    }
}

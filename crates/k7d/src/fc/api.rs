//! Minimal HTTP/1.1 client for Firecracker's API socket.
//!
//! The surface k7d needs is six calls (`PUT /boot-source`,
//! `PUT /machine-config`, `PUT /vsock`, `PUT /actions`, `PATCH /vm`,
//! `GET /`), all of them a single small JSON body over a Unix socket
//! that k7d itself created the chroot for. `reqwest`/`hyper` would add
//! a TLS stack, an async runtime and a few hundred pinned crates to do
//! that, so this is written out: one request per connection with
//! `Connection: close`, a bounded response read, and every non-2xx
//! turned into an error carrying Firecracker's own `fault_message`.
//!
//! Shapes come from the pinned release's swagger
//! (`firecracker_spec-<ver>.yaml`, mirrored in
//! `reference/firecracker/src/firecracker/swagger/firecracker.yaml`).

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::FcError;

/// Largest API response k7d will read. Firecracker's replies are a
/// few hundred bytes (`InstanceInfo`) or empty (`204`); the cap exists
/// so a wedged socket cannot grow the daemon's heap.
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// Per-request socket timeout. Every call here is local and answered in
/// microseconds; a blocking read with no timeout would wedge the
/// daemon's create path forever if Firecracker stopped serving.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Timeout for the two snapshot calls. A `Full` snapshot writes the
/// whole guest RAM synchronously and a `LoadSnapshot` of a large guest
/// faults its state in, so these are not "answered in microseconds".
const SNAPSHOT_TIMEOUT: Duration = Duration::from_secs(120);

/// Boot source (`PUT /boot-source`). Paths are **inside the chroot**.
#[derive(Debug, Serialize)]
pub struct BootSource {
    /// Guest kernel, chroot-relative (`/vmlinux`).
    pub kernel_image_path: String,
    /// Initramfs, chroot-relative (`/initramfs.cpio.gz`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initrd_path: Option<String>,
    /// Kernel command line. Firecracker appends its own
    /// `virtio_mmio.device=` tokens for legacy (`MPTable`) boot.
    pub boot_args: String,
}

/// Machine configuration (`PUT /machine-config`).
#[derive(Debug, Serialize)]
pub struct MachineConfig {
    /// vCPU count.
    pub vcpu_count: u32,
    /// Guest RAM in MiB.
    pub mem_size_mib: u64,
    /// Dirty-page tracking. Off unless Diff snapshots need it.
    pub track_dirty_pages: bool,
}

/// vsock device (`PUT /vsock`). `uds_path` is chroot-relative; the host
/// sees it at `<chroot>/run/v.sock`.
#[derive(Debug, Serialize)]
pub struct VsockDevice {
    /// Guest-side CID. Always [`super::FC_GUEST_CID`] — the guest is
    /// reachable through the UDS, not through the host's vsock namespace.
    pub guest_cid: u32,
    /// Host UDS path inside the chroot.
    pub uds_path: String,
}

/// A virtio-block device (`PUT /drives/{drive_id}`). `path_on_host` is
/// **inside the chroot**.
#[derive(Debug, Serialize)]
pub struct Drive {
    /// Identity used in the URI and by [`FcApi::patch_drive`].
    pub drive_id: String,
    /// Backing file, chroot-relative (`/img/…`, `/disk/…`).
    pub path_on_host: String,
    /// The guest's `root=` device. Always false here: k7d's guests
    /// mount every disk by `k7d.blk=` from an initramfs.
    pub is_root_device: bool,
    /// Read-only devices are the erofs images and the image slots.
    pub is_read_only: bool,
    /// `Unsafe` (host page cache, no `fsync` per write) or `Writeback`.
    pub cache_type: &'static str,
    /// `Sync` or `Async` (`io_uring`).
    pub io_engine: &'static str,
}

/// Host page cache, no flush-through. The same durability the native
/// backend's `pwrite` block device gives, so a pod does not get
/// different crash semantics from its choice of VMM.
pub const CACHE_TYPE_UNSAFE: &str = "Unsafe";

/// Blocking `pread`/`pwrite` on the device thread. `Async` (`io_uring`)
/// is the other option; `Sync` is what the native backend does and the
/// only one Firecracker supports for every host kernel it runs on.
pub const IO_ENGINE_SYNC: &str = "Sync";

/// Fields of a drive that can be changed on a live VM
/// (`PATCH /drives/{drive_id}`).
#[derive(Debug, Serialize)]
struct PartialDrive {
    drive_id: String,
    path_on_host: String,
}

/// A virtio-net device (`PUT /network-interfaces/{iface_id}`).
///
/// `host_dev_name` is a TAP that already exists on the host: k7d's
/// `network.rs` created it on the cluster bridge and detached its own
/// fd so Firecracker can claim it ([`crate::network::TapDevice`]).
#[derive(Debug, Serialize)]
pub struct NetworkInterface {
    /// Identity used in the URI (and in `network_overrides`).
    pub iface_id: String,
    /// Existing host TAP interface name.
    pub host_dev_name: String,
    /// MAC the guest sees, `aa:bb:…` from the bridge allocator.
    pub guest_mac: String,
}

/// Instance state as reported by `GET /`.
#[derive(Debug, Deserialize)]
pub struct InstanceInfo {
    /// `Not started` | `Running` | `Paused`.
    pub state: String,
    /// Firecracker build version, e.g. `1.16.1`.
    pub vmm_version: String,
}

/// Firecracker's error body.
#[derive(Debug, Deserialize)]
struct FaultBody {
    fault_message: String,
}

/// A client bound to one microVM's API socket.
#[derive(Debug, Clone)]
pub struct FcApi {
    socket: PathBuf,
}

impl FcApi {
    /// Bind to the API socket at `socket` (host path).
    #[must_use]
    pub fn new(socket: &Path) -> Self {
        Self {
            socket: socket.to_path_buf(),
        }
    }

    /// Host path of the API socket.
    #[must_use]
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// `PUT /boot-source`.
    pub fn put_boot_source(&self, body: &BootSource) -> Result<(), FcError> {
        self.send_json("PUT", "/boot-source", body)
    }

    /// `PUT /machine-config`.
    pub fn put_machine_config(&self, body: &MachineConfig) -> Result<(), FcError> {
        self.send_json("PUT", "/machine-config", body)
    }

    /// `PUT /vsock`.
    pub fn put_vsock(&self, body: &VsockDevice) -> Result<(), FcError> {
        self.send_json("PUT", "/vsock", body)
    }

    /// `PUT /drives/{drive_id}` — declare a block device before boot.
    ///
    /// Order matters and is the caller's: Firecracker keeps drives in
    /// the order they are declared, and that is the order the guest
    /// names them `/dev/vda`, `/dev/vdb`, … So this must be called in
    /// the same order the shim computed those names in.
    pub fn put_drive(&self, drive: &Drive) -> Result<(), FcError> {
        self.send_json("PUT", &format!("/drives/{}", drive.drive_id), drive)
    }

    /// `PATCH /drives/{drive_id}` — repoint a declared drive at another
    /// backing file, on a **running** VM.
    ///
    /// Firecracker re-opens the path and re-reads its size, then
    /// signals a config change to the guest driver. This is the
    /// no-hotplug answer to a second container's image arriving after
    /// boot (the image-slot late fill): the native
    /// backend fills the slot file through its own boot-time fd, which
    /// an out-of-process VMM does not let k7d do.
    pub fn patch_drive(&self, drive_id: &str, path_on_host: &str) -> Result<(), FcError> {
        self.send_json(
            "PATCH",
            &format!("/drives/{drive_id}"),
            &PartialDrive {
                drive_id: drive_id.to_string(),
                path_on_host: path_on_host.to_string(),
            },
        )
    }

    /// `PUT /network-interfaces/{iface_id}`.
    pub fn put_network_interface(&self, iface: &NetworkInterface) -> Result<(), FcError> {
        self.send_json(
            "PUT",
            &format!("/network-interfaces/{}", iface.iface_id),
            iface,
        )
    }

    /// `PUT /snapshot/create` — the VM must be paused. Paths are inside
    /// the chroot; Firecracker creates (or truncates) both files as the
    /// jailed uid.
    pub fn create_snapshot(
        &self,
        body: &super::snapshot::SnapshotCreateParams,
    ) -> Result<(), FcError> {
        self.send_json_with("PUT", "/snapshot/create", body, SNAPSHOT_TIMEOUT)
    }

    /// `PUT /snapshot/load` — only legal on a fresh, unconfigured VMM.
    /// On failure Firecracker exits, so the caller must treat an error
    /// here as "the process is gone", not "retry".
    pub fn load_snapshot(&self, body: &super::snapshot::SnapshotLoadParams) -> Result<(), FcError> {
        self.send_json_with("PUT", "/snapshot/load", body, SNAPSHOT_TIMEOUT)
    }

    /// `PUT /actions {"action_type": "InstanceStart"}` — boots the guest.
    pub fn instance_start(&self) -> Result<(), FcError> {
        self.send_raw(
            "PUT",
            "/actions",
            Some("{\"action_type\":\"InstanceStart\"}"),
        )
        .map(|_| ())
    }

    /// `PATCH /vm {"state": "Paused"|"Resumed"}`.
    pub fn set_vm_state(&self, state: &str) -> Result<(), FcError> {
        let body = format!("{{\"state\":\"{state}\"}}");
        self.send_raw("PATCH", "/vm", Some(&body)).map(|_| ())
    }

    /// `GET /` — instance state and VMM version.
    pub fn instance_info(&self) -> Result<InstanceInfo, FcError> {
        let body = self.send_raw("GET", "/", None)?;
        serde_json::from_str(&body).map_err(|e| FcError::Api {
            method: "GET",
            uri: "/".to_string(),
            message: format!("decode InstanceInfo from {body:?}: {e}"),
        })
    }

    fn send_json<T: Serialize>(
        &self,
        method: &'static str,
        uri: &str,
        body: &T,
    ) -> Result<(), FcError> {
        self.send_json_with(method, uri, body, REQUEST_TIMEOUT)
    }

    fn send_json_with<T: Serialize>(
        &self,
        method: &'static str,
        uri: &str,
        body: &T,
        timeout: Duration,
    ) -> Result<(), FcError> {
        let json = serde_json::to_string(body).map_err(|e| FcError::Api {
            method,
            uri: uri.to_string(),
            message: format!("encode request: {e}"),
        })?;
        self.send_raw_with(method, uri, Some(&json), timeout)
            .map(|_| ())
    }

    /// One request, one connection. Returns the response body.
    fn send_raw(
        &self,
        method: &'static str,
        uri: &str,
        body: Option<&str>,
    ) -> Result<String, FcError> {
        self.send_raw_with(method, uri, body, REQUEST_TIMEOUT)
    }

    fn send_raw_with(
        &self,
        method: &'static str,
        uri: &str,
        body: Option<&str>,
        timeout: Duration,
    ) -> Result<String, FcError> {
        let fail = |message: String| FcError::Api {
            method,
            uri: uri.to_string(),
            message,
        };
        let mut stream = UnixStream::connect(&self.socket)
            .map_err(|e| fail(format!("connect {}: {e}", self.socket.display())))?;
        stream
            .set_read_timeout(Some(timeout))
            .and_then(|()| stream.set_write_timeout(Some(timeout)))
            .map_err(|e| fail(format!("set socket timeouts: {e}")))?;

        let payload = body.unwrap_or("");
        let request = format!(
            "{method} {uri} HTTP/1.1\r\n\
             Host: localhost\r\n\
             Accept: application/json\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\r\n{payload}",
            payload.len(),
        );
        stream
            .write_all(request.as_bytes())
            .and_then(|()| stream.flush())
            .map_err(|e| fail(format!("write request: {e}")))?;

        // Firecracker's micro-http ignores `Connection: close` and holds
        // the socket open, so EOF is not the frame terminator: reading
        // to it costs a full `REQUEST_TIMEOUT` on every call and then
        // fails with EAGAIN (CHALLENGES #214). Frame on `Content-Length`
        // instead — the only body encoding Firecracker's API emits.
        let mut raw = Vec::new();
        let mut buf = [0u8; 4096];
        let want = loop {
            if let Some(total) = complete_response_len(&raw) {
                break total;
            }
            let n = stream
                .read(&mut buf)
                .map_err(|e| fail(format!("read response: {e}")))?;
            if n == 0 {
                break raw.len();
            }
            raw.extend_from_slice(&buf[..n]);
            if raw.len() > MAX_RESPONSE_BYTES {
                return Err(fail(format!(
                    "response exceeded {MAX_RESPONSE_BYTES} bytes"
                )));
            }
        };
        let text = String::from_utf8_lossy(&raw[..want.min(raw.len())]).into_owned();
        let (status, response_body) = split_response(&text).map_err(fail)?;
        if !(200..300).contains(&status) {
            let detail = serde_json::from_str::<FaultBody>(&response_body)
                .map(|f| f.fault_message)
                .unwrap_or(response_body);
            return Err(FcError::Api {
                method,
                uri: uri.to_string(),
                message: format!("HTTP {status}: {detail}"),
            });
        }
        Ok(response_body)
    }
}

/// Total length of `raw` once it holds a whole response, or `None`
/// while more bytes are needed.
///
/// A response with no `Content-Length` (Firecracker answers `204 No
/// Content` to every successful `PUT`/`PATCH`) ends at its blank line.
fn complete_response_len(raw: &[u8]) -> Option<usize> {
    let head_end = raw.windows(4).position(|w| w == b"\r\n\r\n")? + 4;
    let head = String::from_utf8_lossy(&raw[..head_end]);
    let content_length = head
        .lines()
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.trim().parse::<usize>().ok())
        .unwrap_or(0);
    (raw.len() >= head_end + content_length).then_some(head_end + content_length)
}

/// Split an HTTP/1.1 response into `(status, body)`.
fn split_response(text: &str) -> Result<(u16, String), String> {
    let (head, body) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| format!("no header/body separator in {text:?}"))?;
    let status_line = head
        .lines()
        .next()
        .ok_or_else(|| format!("empty response head in {text:?}"))?;
    let code = status_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| format!("malformed status line {status_line:?}"))?;
    let status = code
        .parse::<u16>()
        .map_err(|e| format!("malformed status code {code:?}: {e}"))?;
    Ok((status, body.to_string()))
}

/// Block until `socket` exists and accepts, or `timeout` elapses.
///
/// Firecracker creates its API socket after the jailer has chrooted and
/// dropped privileges, so "the jailer returned" is not "the API is up".
/// Configuring against a socket that is not there yet is the classic
/// spurious `ENOENT` on this path.
pub fn wait_for_socket(socket: &Path, timeout: Duration) -> Result<(), FcError> {
    let deadline = Instant::now() + timeout;
    loop {
        if socket.exists() && UnixStream::connect(socket).is_ok() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(FcError::SocketTimeout {
                path: socket.to_path_buf(),
                timeout,
            });
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_response_reads_status_and_body() {
        let (status, body) =
            split_response("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}").expect("parse");
        assert_eq!(status, 200);
        assert_eq!(body, "{}");
    }

    #[test]
    fn split_response_is_loud_on_garbage() {
        let err = split_response("not http").expect_err("must not guess");
        assert!(err.contains("separator"), "{err}");
    }

    #[test]
    fn a_204_is_complete_at_its_blank_line() {
        // Firecracker's answer to every successful PUT. Waiting for a
        // body here is what used to cost a whole request timeout.
        let raw = b"HTTP/1.1 204 No Content\r\nServer: Firecracker API\r\n\r\n";
        assert_eq!(complete_response_len(raw), Some(raw.len()));
    }

    #[test]
    fn a_body_is_awaited_to_its_content_length() {
        let head = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n";
        assert_eq!(complete_response_len(head), None);
        assert_eq!(complete_response_len(b"HTTP/1.1 200 OK\r\n"), None);
        let whole = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        assert_eq!(complete_response_len(whole), Some(whole.len()));
        // A keep-alive socket can carry the next response's bytes into
        // the same read; the frame must stop at this one's end.
        let extra = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhelloHTTP/1.1";
        assert_eq!(complete_response_len(extra), Some(whole.len()));
    }

    #[test]
    fn content_length_is_matched_case_insensitively() {
        let raw = b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\n{}";
        assert_eq!(complete_response_len(raw), Some(raw.len()));
    }

    #[test]
    fn fault_body_decodes() {
        let f: FaultBody = serde_json::from_str(r#"{"fault_message":"boom"}"#).expect("fault body");
        assert_eq!(f.fault_message, "boom");
    }
}

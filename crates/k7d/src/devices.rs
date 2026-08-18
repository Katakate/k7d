//! Virtio device setup: virtiofs, virtio-net, vsock, serial.

use std::io;
use std::sync::{Arc, Mutex};

use vm_superio::serial::NoEvents;
use vm_superio::{Serial, Trigger};

/// Serial interrupt trigger backed by an eventfd.
/// When the serial device needs attention, it writes to the eventfd
/// which can be connected to a KVM irqfd for guest interrupt delivery.
#[derive(Debug, Clone)]
pub struct SerialTrigger {
    evt: Option<Arc<vmm_sys_util::eventfd::EventFd>>,
}

impl SerialTrigger {
    /// Create a trigger with no IRQ delivery (polling mode).
    #[must_use]
    pub fn noop() -> Self {
        Self { evt: None }
    }

    /// Create a trigger backed by an eventfd.
    #[must_use]
    pub fn with_eventfd(evt: Arc<vmm_sys_util::eventfd::EventFd>) -> Self {
        Self { evt: Some(evt) }
    }
}

impl Trigger for SerialTrigger {
    type E = io::Error;

    fn trigger(&self) -> io::Result<()> {
        if let Some(ref evt) = self.evt {
            evt.write(1).map_err(io::Error::other)?;
        }
        Ok(())
    }
}

/// Thread-safe wrapper around the serial device and its output buffer.
#[derive(Debug)]
pub struct SerialDevice {
    pub serial: Serial<SerialTrigger, NoEvents, Vec<u8>>,
}

impl Default for SerialDevice {
    fn default() -> Self {
        Self::new()
    }
}

impl SerialDevice {
    /// Create a new serial device writing to an in-memory buffer.
    #[must_use]
    pub fn new() -> Self {
        Self::with_trigger(SerialTrigger::noop())
    }

    /// Create a serial device that raises its interrupt through
    /// `trigger` (wire it to an irqfd on [`SERIAL_IRQ`]).
    ///
    /// The trigger is load-bearing for guest USERSPACE console writes:
    /// kernel printk polls LSR, but the 8250 tty path drains its 4 KiB
    /// xmit buffer on THRE interrupts. With a no-op trigger those never
    /// fire, so any guest process that logs more than 4 KiB to
    /// `/dev/console` blocks in `write(2)` forever — for the k7-agent
    /// (guest PID 1) that wedged its vsock accept loop and took the
    /// whole agent down under exec-heavy load.
    #[must_use]
    pub fn with_trigger(trigger: SerialTrigger) -> Self {
        let serial = Serial::with_events(trigger, NoEvents, Vec::new());
        Self { serial }
    }

    /// Read one byte at the given offset (guest IN instruction).
    pub fn read(&mut self, offset: u8) -> u8 {
        self.serial.read(offset)
    }

    /// Write one byte at the given offset (guest OUT instruction).
    pub fn write(&mut self, offset: u8, value: u8) {
        self.serial.write(offset, value).ok();
    }

    /// Return all output produced so far.
    #[must_use]
    pub fn output(&self) -> &[u8] {
        self.serial.writer()
    }
}

/// COM1 base I/O port (kernel console).
pub const SERIAL_PORT_BASE: u16 = 0x3f8;
/// COM2 base I/O port (agent communication).
pub const SERIAL2_PORT_BASE: u16 = 0x2f8;
/// Serial port range size (8 registers).
pub const SERIAL_PORT_SIZE: u16 = 0x8;
/// COM1 IRQ line.
pub const SERIAL_IRQ: u32 = 4;

/// Shared handle to a serial device for use across threads.
pub type SharedSerialDevice = Arc<Mutex<SerialDevice>>;

/// Create a new shared serial device with a real interrupt trigger
/// (see [`SerialDevice::with_trigger`]).
#[must_use]
pub fn create_serial_device_with_trigger(trigger: SerialTrigger) -> SharedSerialDevice {
    Arc::new(Mutex::new(SerialDevice::with_trigger(trigger)))
}

/// Serial device that writes to a pipe for agent communication.
#[derive(Debug)]
pub struct PipeSerialDevice {
    /// The serial emulator.
    pub serial: Serial<SerialTrigger, NoEvents, PipeWriter>,
    /// Read end of the pipe (host reads agent responses from here).
    pub read_fd: std::os::unix::io::RawFd,
}

/// Writer that sends bytes to a pipe.
#[derive(Debug)]
pub struct PipeWriter {
    fd: std::os::unix::io::RawFd,
}

impl Drop for PipeWriter {
    fn drop(&mut self) {
        // SAFETY: fd is the pipe write end this writer owns; closed once
        // here (PipeWriter is not Clone).
        unsafe { libc::close(self.fd) };
    }
}

impl std::io::Write for PipeWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // SAFETY: self.fd is a valid pipe write end, buf is a valid byte slice.
        let ret = unsafe { libc::write(self.fd, buf.as_ptr().cast::<libc::c_void>(), buf.len()) };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(ret as usize)
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl PipeSerialDevice {
    /// Create a new pipe-backed serial device with optional IRQ trigger.
    /// Returns the device and a raw fd (unused, kept for API compat).
    pub fn new() -> io::Result<(Self, std::os::unix::io::RawFd)> {
        Self::with_trigger(SerialTrigger::noop())
    }

    /// Create with a specific trigger (for IRQ delivery).
    pub fn with_trigger(trigger: SerialTrigger) -> io::Result<(Self, std::os::unix::io::RawFd)> {
        // Pipe for guest output → host (agent responses)
        let mut output_pipe = [0i32; 2];
        // SAFETY: output_pipe is a valid 2-element array for pipe(2) to fill.
        if unsafe { libc::pipe(output_pipe.as_mut_ptr()) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let output_read_fd = output_pipe[0];
        let output_write_fd = output_pipe[1];

        let writer = PipeWriter {
            fd: output_write_fd,
        };
        let serial = Serial::with_events(trigger, NoEvents, writer);

        Ok((
            Self {
                serial,
                read_fd: output_read_fd,
            },
            0, // unused
        ))
    }

    /// Read one byte at the given offset (guest IN instruction).
    pub fn read(&mut self, offset: u8) -> u8 {
        self.serial.read(offset)
    }

    /// Write one byte at the given offset (guest OUT instruction).
    pub fn write(&mut self, offset: u8, value: u8) {
        self.serial.write(offset, value).ok();
    }

    /// Enqueue a byte into the serial input FIFO (host → guest).
    pub fn enqueue_input(&mut self, byte: u8) {
        self.serial.enqueue_raw_bytes(&[byte]).ok();
    }
}

impl Drop for PipeSerialDevice {
    fn drop(&mut self) {
        // SAFETY: read_fd is the pipe read end this device owns; consumers
        // (`AgentClient::new`) dup it rather than taking ownership, and the
        // device is not Clone, so this is the single close. Without it every
        // dropped VM leaked the pipe pair — a fork-heavy daemon hit EMFILE
        // after ~500 forks (found by the the referenced work repro loop).
        unsafe { libc::close(self.read_fd) };
    }
}

/// Shared handle to a pipe serial device.
pub type SharedPipeSerialDevice = Arc<Mutex<PipeSerialDevice>>;

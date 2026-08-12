use std::fs::{self, OpenOptions};
use std::mem::{align_of, size_of};
use std::os::fd::{AsRawFd, RawFd};
use std::ptr;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, ensure};

const DM_IOCTL: u32 = 0xfd;
const DM_VERSION_CMD: u32 = 0;
const DM_DEV_CREATE_CMD: u32 = 3;
const DM_DEV_REMOVE_CMD: u32 = 4;
const DM_DEV_SUSPEND_CMD: u32 = 6;
const DM_TABLE_LOAD_CMD: u32 = 9;
const DM_READONLY_FLAG: u32 = 1;
const DM_PERSISTENT_DEV_FLAG: u32 = 8;
const DM_NAME_LEN: usize = 128;
const DM_UUID_LEN: usize = 129;
const DM_MAX_TYPE_NAME: usize = 16;
const DM_NAME: &str = "nanocodex-root";
const DEVICE_WAIT: Duration = Duration::from_secs(5);

#[repr(C)]
#[derive(Clone, Copy)]
struct DmIoctl {
    version: [u32; 3],
    data_size: u32,
    data_start: u32,
    target_count: u32,
    open_count: i32,
    flags: u32,
    event_nr: u32,
    padding: u32,
    dev: u64,
    name: [libc::c_char; DM_NAME_LEN],
    uuid: [libc::c_char; DM_UUID_LEN],
    data: [libc::c_char; 7],
}

impl DmIoctl {
    fn new(data_size: usize, target_count: u32, flags: u32, name: bool) -> anyhow::Result<Self> {
        let mut value = Self {
            version: [4, 0, 0],
            data_size: data_size
                .try_into()
                .context("device-mapper buffer is too large")?,
            data_start: size_of::<Self>()
                .try_into()
                .context("device-mapper header is too large")?,
            target_count,
            open_count: 0,
            flags,
            event_nr: 0,
            padding: 0,
            dev: 0,
            name: [0; DM_NAME_LEN],
            uuid: [0; DM_UUID_LEN],
            data: [0; 7],
        };
        if name {
            copy_c_string(&mut value.name, DM_NAME)?;
        }
        Ok(value)
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct DmTargetSpec {
    sector_start: u64,
    length: u64,
    status: i32,
    next: u32,
    target_type: [libc::c_char; DM_MAX_TYPE_NAME],
}

#[derive(Debug, PartialEq, Eq)]
struct VerityConfig {
    data_blocks: u64,
    hash_start_block: u64,
    root_hash: String,
    salt: String,
}

impl VerityConfig {
    fn parse(value: &str) -> anyhow::Result<Self> {
        let fields: Vec<_> = value.split(':').collect();
        ensure!(
            fields.len() == 4,
            "KRUN_TEE_VERITY must be DATA_BLOCKS:HASH_START_BLOCK:ROOT_HASH:SALT"
        );
        let data_blocks = fields[0]
            .parse::<u64>()
            .context("invalid dm-verity data block count")?;
        let hash_start_block = fields[1]
            .parse::<u64>()
            .context("invalid dm-verity hash start block")?;
        ensure!(
            data_blocks > 0,
            "dm-verity data block count must be non-zero"
        );
        ensure!(
            hash_start_block >= data_blocks,
            "dm-verity hash tree overlaps filesystem data"
        );
        validate_sha256_hex("root hash", fields[2])?;
        validate_sha256_hex("salt", fields[3])?;
        data_blocks
            .checked_mul(8)
            .context("dm-verity sector count overflow")?;

        Ok(Self {
            data_blocks,
            hash_start_block,
            root_hash: fields[2].to_owned(),
            salt: fields[3].to_owned(),
        })
    }

    fn sectors(&self) -> u64 {
        self.data_blocks * 8
    }

    fn target_parameters(&self) -> String {
        format!(
            "1 /dev/vda /dev/vda 4096 4096 {} {} sha256 {} {}",
            self.data_blocks, self.hash_start_block, self.root_hash, self.salt
        )
    }
}

fn validate_sha256_hex(label: &str, value: &str) -> anyhow::Result<()> {
    ensure!(
        value.len() == 64,
        "dm-verity {label} must contain 64 hex digits"
    );
    ensure!(
        value.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "dm-verity {label} contains a non-hex character"
    );
    Ok(())
}

pub fn create_verity_mapping(value: &str) -> anyhow::Result<()> {
    let config = VerityConfig::parse(value)?;
    wait_for_device("/dev/vda")?;
    let control = open_control()?;
    let fd = control.as_raw_fd();

    let version = ioctl_header(
        fd,
        DM_VERSION_CMD,
        DmIoctl::new(size_of::<DmIoctl>(), 0, 0, false)?,
    )
    .context("query device-mapper version")?;
    ensure!(
        version.version[0] == 4,
        "unsupported device-mapper major version"
    );

    ioctl_header(
        fd,
        DM_DEV_CREATE_CMD,
        DmIoctl::new(size_of::<DmIoctl>(), 0, DM_PERSISTENT_DEV_FLAG, true)?,
    )
    .context("create device-mapper device")?;

    let result = (|| {
        load_table(fd, &config).context("load dm-verity table")?;
        ioctl_header(
            fd,
            DM_DEV_SUSPEND_CMD,
            DmIoctl::new(size_of::<DmIoctl>(), 0, 0, true)?,
        )
        .context("activate dm-verity table")?;
        ensure!(
            fs::metadata("/dev/dm-0").is_ok(),
            "device mapper did not create /dev/dm-0"
        );
        Ok(())
    })();

    if result.is_err() {
        let _ = ioctl_header(
            fd,
            DM_DEV_REMOVE_CMD,
            DmIoctl::new(size_of::<DmIoctl>(), 0, 0, true)?,
        );
    }
    result
}

fn wait_for_device(path: &str) -> anyhow::Result<()> {
    let deadline = Instant::now() + DEVICE_WAIT;
    loop {
        match fs::metadata(path) {
            Ok(_) => return Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).with_context(|| format!("inspect {path}")),
        }
        ensure!(Instant::now() < deadline, "timed out waiting for {path}");
        thread::sleep(Duration::from_millis(10));
    }
}

fn open_control() -> anyhow::Result<std::fs::File> {
    let deadline = Instant::now() + DEVICE_WAIT;
    loop {
        match OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/mapper/control")
        {
            Ok(control) => return Ok(control),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("open /dev/mapper/control"),
        }
        ensure!(
            Instant::now() < deadline,
            "timed out waiting for /dev/mapper/control"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

fn load_table(fd: RawFd, config: &VerityConfig) -> anyhow::Result<()> {
    let mut buffer = table_buffer(config)?;
    unsafe { ioctl(fd, DM_TABLE_LOAD_CMD, buffer.as_mut_ptr().cast::<DmIoctl>()) }
}

fn table_buffer(config: &VerityConfig) -> anyhow::Result<Vec<u64>> {
    let parameters = config.target_parameters();
    let target_bytes = size_of::<DmTargetSpec>()
        .checked_add(parameters.len())
        .and_then(|size| size.checked_add(1))
        .context("dm-verity target size overflow")?;
    let target_bytes = align_up(target_bytes, align_of::<u64>())?;
    let buffer_bytes = size_of::<DmIoctl>()
        .checked_add(target_bytes)
        .context("dm-verity table buffer overflow")?;
    let mut buffer = vec![0_u64; buffer_bytes.div_ceil(size_of::<u64>())];
    let base = buffer.as_mut_ptr().cast::<u8>();

    let header = DmIoctl::new(buffer_bytes, 1, DM_READONLY_FLAG, true)?;
    let mut target_type = [0; DM_MAX_TYPE_NAME];
    copy_c_string(&mut target_type, "verity")?;
    let target = DmTargetSpec {
        sector_start: 0,
        length: config.sectors(),
        status: 0,
        next: target_bytes
            .try_into()
            .context("dm-verity target is too large")?,
        target_type,
    };

    unsafe {
        ptr::write(base.cast::<DmIoctl>(), header);
        let target_ptr = base.add(size_of::<DmIoctl>());
        ptr::write(target_ptr.cast::<DmTargetSpec>(), target);
        ptr::copy_nonoverlapping(
            parameters.as_ptr(),
            target_ptr.add(size_of::<DmTargetSpec>()),
            parameters.len(),
        );
    }
    Ok(buffer)
}

fn ioctl_header(fd: RawFd, command: u32, mut header: DmIoctl) -> anyhow::Result<DmIoctl> {
    unsafe { ioctl(fd, command, &mut header)? };
    Ok(header)
}

unsafe fn ioctl(fd: RawFd, command: u32, value: *mut DmIoctl) -> anyhow::Result<()> {
    let request = ioctl_request(command)?;
    if unsafe { libc::ioctl(fd, request as _, value) } < 0 {
        return Err(std::io::Error::last_os_error()).context("device-mapper ioctl");
    }
    Ok(())
}

fn ioctl_request(command: u32) -> anyhow::Result<libc::c_ulong> {
    const IOC_WRITE: u32 = 1;
    const IOC_READ: u32 = 2;
    const IOC_DIRSHIFT: u32 = 30;
    const IOC_SIZESHIFT: u32 = 16;
    const IOC_TYPESHIFT: u32 = 8;

    let size: u32 = size_of::<DmIoctl>()
        .try_into()
        .context("device-mapper ioctl header is too large")?;
    Ok((((IOC_READ | IOC_WRITE) << IOC_DIRSHIFT)
        | (size << IOC_SIZESHIFT)
        | (DM_IOCTL << IOC_TYPESHIFT)
        | command) as libc::c_ulong)
}

fn copy_c_string<const N: usize>(
    target: &mut [libc::c_char; N],
    value: &str,
) -> anyhow::Result<()> {
    ensure!(value.len() < N, "device-mapper string is too long");
    for (destination, source) in target.iter_mut().zip(value.bytes()) {
        *destination = source as libc::c_char;
    }
    Ok(())
}

fn align_up(value: usize, alignment: usize) -> anyhow::Result<usize> {
    ensure!(alignment.is_power_of_two(), "invalid alignment");
    value
        .checked_add(alignment - 1)
        .map(|value| value & !(alignment - 1))
        .context("alignment overflow")
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: &str = "fba7bd2a668750b4c213330cedce88333901e41d496f4b69787c99abcada4476";
    const SALT: &str = "d3af69fdb66bc3cb76230718ef578805c7d38cdd61d5c83a7bcf17b47d61dc4e";

    #[test]
    fn parses_bounded_verity_descriptor() {
        let config = VerityConfig::parse(&format!("32768:32768:{ROOT}:{SALT}")).unwrap();

        assert_eq!(config.data_blocks, 32768);
        assert_eq!(config.hash_start_block, 32768);
        assert_eq!(config.sectors(), 262144);
        assert_eq!(
            config.target_parameters(),
            format!("1 /dev/vda /dev/vda 4096 4096 32768 32768 sha256 {ROOT} {SALT}")
        );
    }

    #[test]
    fn rejects_overlapping_or_malformed_verity_descriptors() {
        assert!(VerityConfig::parse(&format!("32768:32767:{ROOT}:{SALT}")).is_err());
        assert!(VerityConfig::parse(&format!("32768:32768:bad:{SALT}")).is_err());
        assert!(VerityConfig::parse(&format!("32768:32768:{ROOT}:bad")).is_err());
        assert!(VerityConfig::parse(&format!("0:0:{ROOT}:{SALT}")).is_err());
    }

    #[test]
    fn matches_linux_device_mapper_uapi_layout_and_requests() {
        assert_eq!(size_of::<DmIoctl>(), 312);
        assert_eq!(size_of::<DmTargetSpec>(), 40);
        assert_eq!(ioctl_request(DM_VERSION_CMD).unwrap(), 0xc138_fd00);
        assert_eq!(ioctl_request(DM_DEV_CREATE_CMD).unwrap(), 0xc138_fd03);
        assert_eq!(ioctl_request(DM_TABLE_LOAD_CMD).unwrap(), 0xc138_fd09);
    }

    #[test]
    fn builds_one_read_only_verity_target() {
        let config = VerityConfig::parse(&format!("32768:32768:{ROOT}:{SALT}")).unwrap();
        let buffer = table_buffer(&config).unwrap();
        let base = buffer.as_ptr().cast::<u8>();
        let header = unsafe { &*base.cast::<DmIoctl>() };
        let target = unsafe { &*base.add(size_of::<DmIoctl>()).cast::<DmTargetSpec>() };

        assert_eq!(header.data_start as usize, size_of::<DmIoctl>());
        assert_eq!(header.target_count, 1);
        assert_eq!(header.flags, DM_READONLY_FLAG);
        assert_eq!(target.sector_start, 0);
        assert_eq!(target.length, 262144);
        assert_eq!(target.next as usize % align_of::<u64>(), 0);
    }
}

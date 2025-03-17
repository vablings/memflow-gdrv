use std::any::Any;
use std::mem;

use memflow::prelude::v1::*;
use memflow_vdm::{PhysicalMemory, *};

use windows::core::{s, Result};
use windows::Win32::Foundation::{CloseHandle, GENERIC_READ, GENERIC_WRITE};
use windows::Win32::Storage::FileSystem::*;
use windows::Win32::System::IO::DeviceIoControl;

use handle::RawHandle;

mod handle;

use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockEncryptMut, KeyIvInit};

static AES_KEY: &[u8; 16] = b"GIGABYTEPASSWORD";
static IV: &[u8; 16] = &[0x0; 16];

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;

/// Compute the checksum that the gigabyte driver checks for when issuing an IOCTL.
fn compute_checksum(input_buffer: &mut Vec<u8>) {
    let mut checksum = 0u8;
    for byte in input_buffer.iter() {
        checksum = checksum.wrapping_add(*byte);
    }
    input_buffer.push(!checksum);
}

/// Encrypt the IOCTL with AES_CBC as the driver expects.
fn aes_encrypt(input_buffer: &mut [u8]) -> Vec<u8> {
    Aes128CbcEnc::new(AES_KEY.into(), IV.into()).encrypt_padded_vec_mut::<Pkcs7>(input_buffer)
}

#[repr(u32)]
enum IoControlCode {
    MapPhysicalMemory = 0xC350200C,
    UnmapPhysicalMemory = 0xC3502010,
}

#[derive(Debug, Default)]
#[repr(C)]
struct PhysicalMemoryMappingRequest {
    size: u64,
    phys_addr: u64,
    section_handle: RawHandle,
    virt_addr: u64,
    obj_handle: RawHandle,
}

#[derive(Clone)]
struct GdrvDriver {
    handle: RawHandle,
}

impl GdrvDriver {
    fn open() -> Result<Self> {
        let handle = unsafe {
            CreateFileA(
                s!(r"\\.\GIOV3"),
                GENERIC_READ.0 | GENERIC_WRITE.0,
                FILE_SHARE_MODE(0),
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )?
        };

        Ok(Self {
            handle: handle.into(),
        })
    }
}

impl Drop for GdrvDriver {
    fn drop(&mut self) {
        if self.handle.is_valid() {
            unsafe {
                let _ = CloseHandle(self.handle.handle());
            }
        }
    }
}

#[derive(Debug)]
struct MapPhysicalMemoryResponse {
    phys_addr: u64,
    obj_handle: RawHandle,
    section_handle: RawHandle,
    size: usize,
    virt_addr: u64,
}

impl PhysicalMemoryResponse for MapPhysicalMemoryResponse {
    #[inline]
    fn as_any(&self) -> &dyn Any {
        self
    }

    #[inline]
    fn phys_addr(&self) -> u64 {
        self.phys_addr
    }

    #[inline]
    fn size(&self) -> usize {
        self.size
    }

    #[inline]
    fn virt_addr(&self) -> u64 {
        self.virt_addr
    }
}

impl PhysicalMemory for GdrvDriver {
    fn map_phys_mem(
        &self,
        addr: u64,
        size: usize,
    ) -> memflow_vdm::Result<PhysicalMemoryResponseBoxed> {
        let mut req = PhysicalMemoryMappingRequest {
            size: size as _,
            phys_addr: addr,
            ..Default::default()
        };

        let mut input_buffer: Vec<u8> = Vec::new();
        input_buffer.extend_from_slice(&addr.to_le_bytes());
        input_buffer.extend_from_slice(&size.to_le_bytes());

        let mut output_buffer = [0u8; 0x10];

        unsafe {
            DeviceIoControl(
                self.handle.handle(),
                IoControlCode::MapPhysicalMemory as _,
                Some(input_buffer.as_ptr() as _),
                input_buffer.len() as _,
                Some(output_buffer.as_mut_ptr() as _),
                output_buffer.len() as u32,
                None,
                None,
            )
            .map_err(memflow_vdm::Error::Windows)?;
        }

        let virt_addr = u64::from_le_bytes(output_buffer[0..8].try_into().unwrap());

        Ok(Box::new(MapPhysicalMemoryResponse {
            phys_addr: addr,
            obj_handle: req.obj_handle,
            section_handle: req.section_handle,
            size,
            virt_addr,
        }))
    }

    fn unmap_phys_mem(&self, mapping: PhysicalMemoryResponseBoxed) -> memflow_vdm::Result<()> {
        let res = mapping
            .as_any()
            .downcast_ref::<MapPhysicalMemoryResponse>()
            .unwrap();

        let req = PhysicalMemoryMappingRequest {
            obj_handle: res.obj_handle,
            section_handle: res.section_handle,
            virt_addr: res.virt_addr(),
            ..Default::default()
        };

        let mut input_buffer: Vec<u8> = Vec::new();
        input_buffer.extend_from_slice(res.virt_addr().as_bytes_mut());

        unsafe {
            DeviceIoControl(
                self.handle.handle(),
                IoControlCode::UnmapPhysicalMemory as _,
                Some(&req as *const _ as *const _),
                mem::size_of::<PhysicalMemoryMappingRequest>() as _,
                None,
                0,
                None,
                None,
            )
            .map_err(memflow_vdm::Error::Windows)
        }
    }
}

#[connector(name = "gdrv3", description = "test")]
pub fn create_connector<'a>(_args: &ConnectorArgs) -> memflow::error::Result<VdmConnector<'a>> {
    let drv = GdrvDriver::open().map_err(|_| {
        Error(ErrorOrigin::Connector, ErrorKind::Uninitialized)
            .log_error("Unable to open a handle to the gdrv3 driver")
    })?;

    init_connector(Box::new(drv)).map_err(|_| {
        Error(ErrorOrigin::Connector, ErrorKind::Uninitialized)
            .log_error("Unable to initialize connector")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_phys_mem() -> memflow_vdm::Result<()> {
        const PAGE_SIZE: usize = 4096;

        let drv = GdrvDriver::open().map_err(memflow_vdm::Error::Windows)?;

        for addr in (0x0..0x10000u64).step_by(PAGE_SIZE) {
            let mapping = drv.map_phys_mem(addr, PAGE_SIZE)?;

            println!(
                "mapped physical memory from {:#X} -> {:#X} (size: {})",
                mapping.phys_addr(),
                mapping.virt_addr(),
                mapping.size(),
            );

            drv.unmap_phys_mem(mapping)?;
        }

        Ok(())
    }
}

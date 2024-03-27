use binrw::{binrw, BinReaderExt, BinResult, BinWriterExt};
use thiserror::Error;

use std::ffi::CString;
use std::io::{Cursor, Seek, SeekFrom};

#[derive(Debug, Error)]
pub enum BBFSError {
    #[error("Filename \"{0}\" is too long (should be 8.3)")]
    FileNameTooLong(String),
}

#[binrw]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum FATEntry {
    #[brw(magic = 0x0000u16)]
    Free,
    #[brw(magic = 0xFFFFu16)]
    EndOfChain,
    #[brw(magic = 0xFFFEu16)]
    BadBlock,
    #[brw(magic = 0xFFFDu16)]
    Reserved,
    Chain(u16),
}

#[binrw]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum FileValid {
    #[brw(magic = 0x00u8)]
    Invalid,
    #[brw(magic = 0x01u8)]
    Valid,
}

#[binrw]
#[derive(Debug, Clone, Copy)]
pub struct FileEntry {
    pub name: [u8; 8],
    pub ext: [u8; 3],
    pub valid: FileValid,
    #[brw(pad_after(2))]
    pub start: FATEntry,
    pub size: u32,
}

#[binrw]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum FSType {
    #[brw(magic = b"BBFS")]
    Bbfs,
    #[brw(magic = b"BBFL")]
    Bbfl,
}

#[binrw]
#[derive(Debug, Clone, Copy)]
pub struct FSFooter {
    pub fs_type: FSType,
    pub seqno: u32,
    pub link_block: u16,
    pub chksum: u16,
}

#[binrw]
#[derive(Debug, Clone, Copy)]
pub struct FSBlock {
    pub fat: [FATEntry; 0x1000],
    pub entries: [FileEntry; 409],
    pub footer: FSFooter,
}

impl FSBlock {
    pub fn read<T: AsRef<[u8]>>(data: T) -> BinResult<Self> {
        let mut cursor = Cursor::new(data.as_ref());
        match <_>::read_be(&mut cursor) {
            Ok(fs) => {
                if data.as_ref().chunks(2).fold(0u16, |a, e| match e {
                    &[upper, lower] => a.wrapping_add(u16::from_be_bytes([upper, lower])),
                    _ => unreachable!(),
                }) != 0xCAD7
                {
                    Err(binrw::Error::AssertFail {
                        pos: 0x3FFE,
                        message: "Invalid checksum".to_string(),
                    })
                } else {
                    Ok(fs)
                }
            }
            Err(e) => Err(e),
        }
    }

    pub fn write(&self) -> BinResult<Vec<u8>> {
        let mut cursor = Cursor::new(vec![]);
        match cursor.write_be(self) {
            Ok(_) => {
                let data = cursor.into_inner();
                let sum = data[..0x3FFE].as_ref().chunks(2).fold(0u16, |a, e| {
                    a.wrapping_add(u16::from_be_bytes(e.try_into().unwrap()))
                });
                let checksum = 0xCAD7u16.wrapping_sub(sum);
                cursor = Cursor::new(data);
                cursor.seek(SeekFrom::End(-2)).unwrap();
                cursor.write_be(&checksum).unwrap();
                Ok(cursor.into_inner())
            }
            Err(e) => Err(e),
        }
    }
}

impl FileEntry {
    pub fn valid(&self) -> bool {
        self.name[0] != 0 && self.valid == FileValid::Valid && self.start != FATEntry::EndOfChain
    }

    pub fn set_filename(&mut self, filename: &str) -> Result<(), BBFSError> {
        let split = filename.split('.').collect::<Vec<_>>();
        let (name, ext) = if split.len() > 1 {
            (split[0], split[1])
        } else {
            (split[0], "")
        };

        if name.len() > 8 || ext.len() > 3 {
            return Err(BBFSError::FileNameTooLong(filename.to_string()));
        }

        self.name
            .copy_from_slice((name.to_owned() + &"\0".repeat(8 - name.len())).as_bytes());
        self.ext
            .copy_from_slice((ext.to_owned() + &"\0".repeat(3 - ext.len())).as_bytes());

        Ok(())
    }

    pub fn get_filename(&self) -> String {
        match self.name.iter().enumerate().find(|(_, &e)| e == 0) {
            Some((index, _)) => CString::new(&self.name[..index]),
            None => CString::new(self.name),
        }
        .expect("Already checked for unexpected nulls")
        .to_string_lossy()
        .into_owned()
    }

    pub fn get_fileext(&self) -> String {
        match self.ext.iter().enumerate().find(|(_, &e)| e == 0) {
            Some((index, _)) => CString::new(&self.ext[..index]),
            None => CString::new(self.ext),
        }
        .expect("Already checked for unexpected nulls")
        .to_string_lossy()
        .into_owned()
    }

    pub fn get_fullname(&self) -> String {
        format!(
            "{}{}{}",
            self.get_filename(),
            if self.get_filename() != "" && self.get_fileext() != "" {
                "."
            } else {
                ""
            },
            self.get_fileext()
        )
    }

    pub fn clear(&mut self) {
        self.name = [0; 8];
        self.ext = [0; 3];
        self.valid = FileValid::Invalid;
        self.start = FATEntry::Free;
        self.size = 0;
    }
}

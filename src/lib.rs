use std::{
    borrow::Cow,
    fs::read,
    io::{self, Cursor, Read, Seek, SeekFrom},
    iter::repeat,
    path::{Path, PathBuf},
};

use bb::CmdHead;
use bbfs::{FATEntry, FSBlock, FSFooter, FileEntry, FileValid};
use binrw::{binrw, helpers::until_eof, BinRead, Endian, VecArgs};
use thiserror::Error;

use crate::bbfs::FSType;

pub mod bbfs;
pub mod ecc;

use ecc::{calc_ecc_512, Ecc};

const BYTES_PER_PAGE: usize = 512;
const PAGES_PER_BLOCK: usize = 32;
const BYTES_PER_BLOCK: usize = BYTES_PER_PAGE * PAGES_PER_BLOCK;

pub const NAND_SIZE_64: usize = 0x4000000;
pub const NAND_SIZE_128: usize = NAND_SIZE_64 * 2;

const SPARE_SIZE_64: usize = 0x10000;
const SPARE_SIZE_128: usize = SPARE_SIZE_64 * 2;
const SPARE_SIZE_64_PAGE: usize = SPARE_SIZE_64 * PAGES_PER_BLOCK;
const SPARE_SIZE_128_PAGE: usize = SPARE_SIZE_128 * PAGES_PER_BLOCK;
const NUM_SPARES_64: usize = SPARE_SIZE_64_PAGE / 0x10;
const NUM_SPARES_128: usize = SPARE_SIZE_128_PAGE / 0x10;

const NUM_SKSA_BLOCKS: usize = 64;
const NUM_FS_BLOCKS: usize = 16;

const BIG_FILE_THRESHOLD: usize = 1024 * 1024;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum NandSize {
    Unspecified,
    Double,
    Single,
}

#[derive(Debug, Default)]
pub struct Nand {
    raw_sksa: bool,
    pub sksa: Vec<u8>,
    pub files: Vec<((String, String), Vec<u8>, bool)>,
}

#[derive(Debug, Error)]
pub enum NandError {
    #[error(
        "Invalid NAND size (got 0x{0:X} bytes, expected 0x{NAND_SIZE_64:X} or 0x{NAND_SIZE_128:X}"
    )]
    InvalidSize(usize),

    #[error("Linked FS block sequence number did not match (got {0:08X}, expected {1:08X}")]
    MismatchedSeqNo(u32, u32),

    #[error("Expected a linked FS block, found a normal FS block")]
    ExpectedLinkBlock,

    #[error("Expected a Chain or EndOfChain block, found {0:?}")]
    UnexpectedBlockType(FATEntry),

    #[error("Tried to read an out-of-range block (0x{0:04X})")]
    OutOfRange(u16),

    #[error("Too many bad blocks")]
    Bad,

    #[error("SK area contains bad blocks")]
    SKBad,

    #[error("The system app size was incorrect")]
    SASizeIncorrect,

    #[error("Not a file: {0}")]
    NotAFile(PathBuf),

    #[error("Invalid filename: {0}")]
    InvalidFileName(PathBuf),

    #[error("Too many files for the selected NAND size ({0})")]
    TooManyFiles(usize),

    #[error("File \"{0}\" too large for filesystem")]
    FileTooLarge(String),

    #[error("Too much file data for the selected NAND size")]
    TooMuchData,

    #[error(transparent)]
    IOError(#[from] io::Error),

    #[error(transparent)]
    BinrwError(#[from] binrw::Error),
}

impl Nand {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn parse<T: AsRef<[u8]>>(file: T, spare: &Option<Spare>) -> Result<Self, NandError> {
        let mut block_buf = [0; BYTES_PER_BLOCK];

        let file = file.as_ref();

        let len = file.len();
        if len != NAND_SIZE_64 && len != NAND_SIZE_128 {
            return Err(NandError::InvalidSize(len));
        }

        let blocks = len / BYTES_PER_BLOCK;

        let mut cursor = Cursor::new(file);

        cursor.seek(SeekFrom::Start(
            ((blocks - NUM_FS_BLOCKS) * BYTES_PER_BLOCK) as _,
        ))?;

        let fs_blocks = <Vec<FSBlock>>::read_be_args(
            &mut cursor,
            VecArgs {
                count: NUM_FS_BLOCKS,
                inner: (),
            },
        )?;

        let mut cur_blocks = vec![];
        cur_blocks.push(Cow::Borrowed(fs_blocks.iter().fold(
            &fs_blocks[0],
            |a, e| {
                if (a.footer.seqno > e.footer.seqno || e.footer.fs_type == FSType::Bbfl)
                    && a.footer.fs_type == FSType::Bbfs
                {
                    a
                } else {
                    e
                }
            },
        )));

        while cur_blocks.last().unwrap().footer.link_block != 0 {
            let prev_block = cur_blocks.last().unwrap();

            cursor.seek(SeekFrom::Start(
                ((prev_block.footer.link_block as usize) * BYTES_PER_BLOCK) as _,
            ))?;
            let link = <FSBlock>::read_be(&mut cursor)?;

            if link.footer.fs_type != FSType::Bbfl {
                return Err(NandError::ExpectedLinkBlock);
            }

            if link.footer.seqno != prev_block.footer.seqno {
                return Err(NandError::MismatchedSeqNo(
                    link.footer.seqno,
                    prev_block.footer.seqno,
                ));
            }

            cur_blocks.push(Cow::Owned(link));
        }

        let next_block = |block| {
            {
                let block = block as usize;
                for (index, fs) in cur_blocks.iter().enumerate() {
                    if index == (block >> 12) {
                        return Ok(&fs.fat[block & 0x0FFF]);
                    }
                }
            }
            Err(NandError::OutOfRange(block))
        };

        let mut files = vec![];

        for fs in &cur_blocks {
            for file in &fs.entries {
                if file.valid() {
                    let filename = (file.get_filename(), file.get_fileext());

                    let mut data = vec![];

                    let mut cur_block = &file.start;

                    while data.len() < file.size as _ {
                        match cur_block {
                            FATEntry::BadBlock
                            | FATEntry::Reserved
                            | FATEntry::Free
                            | FATEntry::EndOfChain => break,
                            FATEntry::Chain(c) => {
                                let c = *c;

                                cursor
                                    .seek(SeekFrom::Start((c as usize * BYTES_PER_BLOCK) as _))?;

                                cursor.read_exact(&mut block_buf)?;

                                data.extend(block_buf);
                                cur_block = next_block(c)?;
                            }
                        }
                    }

                    files.push((filename, data, cur_block == &FATEntry::EndOfChain));
                }
            }
        }

        let (raw_sksa, sksa) = if let Some(spare) = spare {
            let mut blocks = vec![];

            let block_spares = spare.block_spares();

            let next_good_block = |start_at| {
                block_spares
                    .iter()
                    .enumerate()
                    .skip(start_at)
                    .find(|(_, block)| !block.bad)
                    .map(|(i, _)| i)
                    .ok_or(NandError::Bad)
            };

            let sk_start = next_good_block(0)?;

            for (sk_block, block) in block_spares.iter().enumerate().skip(sk_start).take(4) {
                if block.bad {
                    return Err(NandError::SKBad);
                }

                cursor.seek(SeekFrom::Start((sk_block * BYTES_PER_BLOCK) as _))?;

                cursor.read_exact(&mut block_buf)?;
                blocks.extend(&block_buf);
            }

            let sa1_cmd_block = next_good_block(sk_start + 4)?;

            cursor.seek(SeekFrom::Start((sa1_cmd_block * BYTES_PER_BLOCK) as _))?;

            cursor.read_exact(&mut block_buf)?;
            blocks.extend(&block_buf);

            cursor.seek(SeekFrom::Start((sa1_cmd_block * BYTES_PER_BLOCK) as _))?;

            let sa1_cmd = CmdHead::read_be(&mut cursor)?;

            let sa1_block = block_spares[sa1_cmd_block].sa_block as usize;

            let mut sa2_cmd_block = sa1_block;

            for _ in 0..(sa1_cmd.size as usize / BYTES_PER_BLOCK) {
                if sa2_cmd_block == 0xFF {
                    return Err(NandError::SASizeIncorrect);
                }

                cursor.seek(SeekFrom::Start((sa2_cmd_block * BYTES_PER_BLOCK) as _))?;

                cursor.read_exact(&mut block_buf)?;
                blocks.extend(&block_buf);

                sa2_cmd_block = block_spares[sa2_cmd_block].sa_block as _;
            }

            if sa2_cmd_block != 0xFF {
                // sa2 found

                let sa2_cmd_block = next_good_block(sa2_cmd_block)?;

                cursor.seek(SeekFrom::Start((sa2_cmd_block * BYTES_PER_BLOCK) as _))?;

                cursor.read_exact(&mut block_buf)?;
                blocks.extend(&block_buf);

                cursor.seek(SeekFrom::Start((sa2_cmd_block * BYTES_PER_BLOCK) as _))?;

                let sa2_cmd = CmdHead::read_be(&mut cursor)?;

                let mut sa2_block = block_spares[sa2_cmd_block].sa_block as usize;

                for _ in 0..(sa2_cmd.size as usize / BYTES_PER_BLOCK) {
                    if sa2_block == 0xFF {
                        return Err(NandError::SASizeIncorrect);
                    }

                    cursor.seek(SeekFrom::Start((sa2_block * BYTES_PER_BLOCK) as _))?;

                    cursor.read_exact(&mut block_buf)?;
                    blocks.extend(&block_buf);

                    sa2_block = block_spares[sa2_block].sa_block as _;
                }
            }

            (false, blocks)
        } else {
            let mut blocks = vec![];
            for block in &cur_blocks[0].fat {
                if block != &FATEntry::Reserved {
                    break;
                }

                cursor.seek(SeekFrom::Start(0))?;

                cursor.read_exact(&mut block_buf)?;
                blocks.extend(&block_buf);
            }

            (true, blocks)
        };

        Ok(Self {
            raw_sksa,
            sksa,
            files,
        })
    }

    pub fn add_file<T: AsRef<Path>>(&mut self, file: T) -> Result<(), NandError> {
        let file = file.as_ref();

        if !file.is_file() {
            return Err(NandError::NotAFile(file.to_owned()));
        }

        let stem = file
            .file_stem()
            .ok_or(NandError::InvalidFileName(file.to_owned()))?;

        let ext = file
            .extension()
            .map(|e| {
                e.to_str()
                    .ok_or(NandError::InvalidFileName(file.to_owned()))
            })
            .transpose()?;

        let stem = stem
            .to_str()
            .ok_or(NandError::InvalidFileName(file.to_owned()))?
            .to_lowercase();

        if stem.len() > 8 || ext.is_some_and(|e| e.len() > 3) {
            return Err(NandError::InvalidFileName(file.to_owned()));
        }

        let filename = (stem, ext.unwrap_or("").into());

        let file = read(file)?;

        let extant_file = self.files.iter_mut().find(|f| f.0 == filename);

        match extant_file {
            Some(f) => {
                f.1 = file;
                f.2 = true;
            }
            None => {
                self.files.push((filename, file, true));
            }
        }

        Ok(())
    }

    pub fn delete_file<T: AsRef<str>>(&mut self, file: T) -> Result<(), NandError> {
        let file = file.as_ref();
        let file = PathBuf::from(file);

        let stem = file
            .file_stem()
            .ok_or(NandError::InvalidFileName(file.to_owned()))?;

        let ext = file
            .extension()
            .map(|e| {
                e.to_str()
                    .ok_or(NandError::InvalidFileName(file.to_owned()))
            })
            .transpose()?;

        let stem = stem
            .to_str()
            .ok_or(NandError::InvalidFileName(file.to_owned()))?
            .to_lowercase();

        let file = (stem, ext.unwrap_or("").into());

        self.files.retain(|(name, _, _)| name != &file);

        Ok(())
    }

    pub fn update_sksa<T: AsRef<[u8]>>(&mut self, sksa: T) {
        self.sksa = sksa.as_ref().into();
    }

    pub fn export(
        &self,
        size: NandSize,
        spare: &Option<Spare>,
        ignore_bad_files: bool,
    ) -> Result<(Vec<u8>, Spare), NandError> {
        let mut rv = vec![];

        let mut spare = if let Some(spare) = spare {
            spare.convert_size(size)
        } else {
            Spare::new(size)
        };

        let block_spares = spare.block_spares();

        let next_good_block = |mut block: usize| {
            while block_spares[block].bad {
                block += 1
            }
            block
        };

        let prev_good_block = |mut block: usize| {
            while block_spares[block].bad {
                block -= 1
            }
            block
        };

        let mut sksa_block_count = 0;

        if self.raw_sksa {
            rv.extend(&self.sksa);
            sksa_block_count += self.sksa.len() / BYTES_PER_BLOCK;
        } else {
            let mut cur_block = 0;

            cur_block = next_good_block(0);

            for _ in 0..cur_block {
                rv.extend(repeat(0xFF).take(BYTES_PER_BLOCK));
            }

            for block in 0..4 {
                rv.extend(&self.sksa[block * BYTES_PER_BLOCK..(block + 1) * BYTES_PER_BLOCK]);
                if block_spares[cur_block + block].bad {
                    return Err(NandError::SKBad);
                }
            }

            cur_block += 4;
            sksa_block_count += 4;

            let sa1_cmd_block = next_good_block(cur_block);

            for _ in cur_block..sa1_cmd_block {
                rv.extend(repeat(0xFF).take(BYTES_PER_BLOCK));
            }

            rv.extend(
                &self.sksa
                    [sksa_block_count * BYTES_PER_BLOCK..(sksa_block_count + 1) * BYTES_PER_BLOCK],
            );

            let mut cursor = Cursor::new(&self.sksa);

            let sa1_cmd = {
                cursor.seek(SeekFrom::Start((sksa_block_count * BYTES_PER_BLOCK) as _))?;
                <CmdHead>::read_be(&mut cursor)?
            };

            sksa_block_count += 1;

            let sa1_start_block = next_good_block(sa1_cmd_block + 1);

            for _ in sa1_cmd_block + 1..sa1_start_block {
                rv.extend(repeat(0xFF).take(BYTES_PER_BLOCK));
            }

            let mut sa1_block = sa1_start_block;

            let mut prev_block = sa1_cmd_block;

            let sa1_block_size = sa1_cmd.size as usize / BYTES_PER_BLOCK;

            for i in 0..sa1_block_size {
                spare.write_page_spares(prev_block, sa1_block);
                rv.extend(
                    &self.sksa[(sksa_block_count + sa1_block_size - i - 1) * BYTES_PER_BLOCK
                        ..(sksa_block_count + sa1_block_size - i) * BYTES_PER_BLOCK],
                );
                prev_block = sa1_block;
                sa1_block = next_good_block(sa1_block + 1);

                for _ in prev_block + 1..sa1_block {
                    rv.extend(repeat(0xFF).take(BYTES_PER_BLOCK));
                }
            }

            spare.write_page_spares(prev_block, sa1_cmd_block);

            sksa_block_count += sa1_block_size;

            if sksa_block_count < self.sksa.len() / BYTES_PER_BLOCK {
                // has sa2
                let sa2_cmd_block = sa1_block;

                spare.write_page_spares(sa2_cmd_block, sa1_start_block);

                rv.extend(
                    &self.sksa[sksa_block_count * BYTES_PER_BLOCK
                        ..(sksa_block_count + 1) * BYTES_PER_BLOCK],
                );

                let sa2_cmd = {
                    cursor.seek(SeekFrom::Start((sksa_block_count * BYTES_PER_BLOCK) as _))?;
                    <CmdHead>::read_be(&mut cursor)?
                };

                sksa_block_count += 1;

                prev_block = sa2_cmd_block;
                let sa2_start_block = next_good_block(sa2_cmd_block + 1);

                for _ in sa2_cmd_block + 1..sa2_start_block {
                    rv.extend(repeat(0xFF).take(BYTES_PER_BLOCK));
                }

                let mut sa2_block = sa2_start_block;

                let sa2_block_size = sa2_cmd.size as usize / BYTES_PER_BLOCK;

                for i in 0..sa2_block_size {
                    spare.write_page_spares(prev_block, sa2_block);
                    rv.extend(
                        &self.sksa[(sksa_block_count + sa2_block_size - i - 1) * BYTES_PER_BLOCK
                            ..(sksa_block_count + sa2_block_size - i) * BYTES_PER_BLOCK],
                    );
                    prev_block = sa2_block;
                    sa2_block = next_good_block(sa2_block + 1);

                    for _ in prev_block + 1..sa2_block {
                        rv.extend(repeat(0xFF).take(BYTES_PER_BLOCK));
                    }
                }

                spare.write_page_spares(prev_block, sa2_cmd_block);

                spare.write_page_spares(0xFF, sa2_start_block);

                sksa_block_count += sa2_block_size;
            } else {
                spare.write_page_spares(0xFF, sa1_start_block);
            }

            while sksa_block_count < NUM_SKSA_BLOCKS {
                rv.extend(repeat(0xFF).take(BYTES_PER_BLOCK));
                sksa_block_count += 1;
            }
        }

        let num_blocks = match size {
            NandSize::Unspecified => unreachable!(),
            NandSize::Double => NAND_SIZE_128 / BYTES_PER_BLOCK,
            NandSize::Single => NAND_SIZE_64 / BYTES_PER_BLOCK,
        };

        for _ in sksa_block_count..num_blocks - NUM_FS_BLOCKS {
            rv.extend(repeat(0xFF).take(BYTES_PER_BLOCK));
        }

        let mut fs_blocks = vec![FSBlock {
            fat: [FATEntry::Free; 0x1000],
            entries: [FileEntry {
                name: Default::default(),
                ext: Default::default(),
                valid: FileValid::Invalid,
                start: FATEntry::Free,
                size: 0,
            }; 409],
            footer: FSFooter {
                fs_type: FSType::Bbfs,
                seqno: 0,
                link_block: 0,
                chksum: 0,
            },
        }];

        if size == NandSize::Double {
            fs_blocks.push(FSBlock {
                fat: [FATEntry::Free; 0x1000],
                entries: [FileEntry {
                    name: Default::default(),
                    ext: Default::default(),
                    valid: FileValid::Invalid,
                    start: FATEntry::Free,
                    size: 0,
                }; 409],
                footer: FSFooter {
                    fs_type: FSType::Bbfl,
                    seqno: 0,
                    link_block: 0,
                    chksum: 0,
                },
            });
        }

        for block in 0..num_blocks {
            if block_spares[block].bad {
                fs_blocks[block >> 12].fat[block & 0x0FFF] = FATEntry::BadBlock;
            }

            if block < sksa_block_count {
                fs_blocks[block >> 12].fat[block & 0x0FFF] = FATEntry::Reserved;
            }

            if block >= num_blocks - NUM_FS_BLOCKS {
                fs_blocks[block >> 12].fat[block & 0x0FFF] = FATEntry::Reserved;
            }
        }

        let mut big_file_block = next_good_block(sksa_block_count);
        let mut small_file_block = prev_good_block(num_blocks - NUM_FS_BLOCKS - 1);

        let mut prev_block = 0;

        let mut next_file = 0;

        for ((name, ext), data) in self.files.iter().filter_map(|(name, data, good)| {
            if *good || ignore_bad_files {
                Some((name, data))
            } else {
                None
            }
        }) {
            let len = data.len();

            let fs = next_file / 409;
            if fs > fs_blocks.len() - 1 {
                return Err(NandError::TooManyFiles(next_file + 1));
            }

            let entry = &mut fs_blocks[fs].entries[next_file % 409];

            let full_name = format!("{}{}{}", name, if ext.is_empty() { "" } else { "." }, ext);

            let mut name = name.as_bytes().to_vec();
            name.resize(8, 0);

            let mut ext = ext.as_bytes().to_vec();
            ext.resize(3, 0);

            entry.name = name
                .try_into()
                .expect("filename should have already been validated");
            entry.ext = ext
                .try_into()
                .expect("extension should have already been validated");

            entry.size = len
                .try_into()
                .map_err(|_| NandError::FileTooLarge(full_name))?;

            entry.valid = FileValid::Valid;

            if len > BIG_FILE_THRESHOLD {
                entry.start = FATEntry::Chain(big_file_block as _);

                for block in 0..len / BYTES_PER_BLOCK {
                    rv[big_file_block * BYTES_PER_BLOCK..(big_file_block + 1) * BYTES_PER_BLOCK]
                        .copy_from_slice(
                            &data[block * BYTES_PER_BLOCK..(block + 1) * BYTES_PER_BLOCK],
                        );

                    prev_block = big_file_block;
                    big_file_block = next_good_block(big_file_block + 1);

                    let fs = prev_block >> 12;
                    if fs > fs_blocks.len() - 1 {
                        return Err(NandError::TooMuchData);
                    }

                    fs_blocks[fs].fat[prev_block & 0x0FFF] = FATEntry::Chain(big_file_block as _);
                }

                fs_blocks[prev_block >> 12].fat[prev_block & 0x0FFF] = FATEntry::EndOfChain;
            } else {
                entry.start = FATEntry::Chain(small_file_block as _);

                for block in 0..len / BYTES_PER_BLOCK {
                    rv[small_file_block * BYTES_PER_BLOCK
                        ..(small_file_block + 1) * BYTES_PER_BLOCK]
                        .copy_from_slice(
                            &data[block * BYTES_PER_BLOCK..(block + 1) * BYTES_PER_BLOCK],
                        );

                    prev_block = small_file_block;
                    small_file_block = prev_good_block(small_file_block - 1);

                    let fs = prev_block >> 12;
                    if fs > fs_blocks.len() - 1 {
                        return Err(NandError::TooMuchData);
                    }

                    fs_blocks[fs].fat[prev_block & 0x0FFF] = FATEntry::Chain(small_file_block as _);
                }

                fs_blocks[prev_block >> 12].fat[prev_block & 0x0FFF] = FATEntry::EndOfChain;
            }

            next_file += 1;
        }

        let fs_nand_start = num_blocks - NUM_FS_BLOCKS;

        let mut fs_block = next_good_block(fs_nand_start);

        let mut fs_nand_blocks = vec![];
        for _ in &fs_blocks {
            fs_nand_blocks.push(fs_block);
            fs_block = next_good_block(fs_block + 1);
        }

        for i in 1..fs_blocks.len() {
            fs_blocks[i - 1].footer.link_block = fs_nand_blocks[i] as _;
        }

        prev_block = fs_nand_start;
        for (&nand_block, fs_block) in fs_nand_blocks.iter().zip(&fs_blocks) {
            for _ in prev_block..nand_block {
                rv.extend(repeat(0xFF).take(BYTES_PER_BLOCK));
            }

            rv.extend(fs_block.write()?);
            prev_block = nand_block + 1;
        }

        while prev_block < num_blocks {
            rv.extend(repeat(0xFF).take(BYTES_PER_BLOCK));
            prev_block += 1;
        }

        for (index, page) in rv.chunks_exact(BYTES_PER_PAGE).enumerate() {
            let (first, second) = calc_ecc_512(page);

            spare.set_page_ecc(index, first, second);
        }

        Ok((rv, spare))
    }
}

#[binrw]
#[derive(Debug)]
#[br(map(|x: u8| {
    match x.count_zeros() {
        0 => Self::Good,
        1 => Self::OneBitError(x),
        _ => Self::Bad(x),
    }
}))]
#[bw(map(|x: &Self| {
    match *x {
        BadBlockIndicator::Good => 0,
        BadBlockIndicator::OneBitError(n) => n,
        BadBlockIndicator::Bad(n) => n
    }
}))]
pub enum BadBlockIndicator {
    Good,
    OneBitError(u8),
    Bad(u8),
}

#[binrw]
#[derive(Debug)]
pub struct SpareBlock {
    sa_block_data: (u8, u8, u8),
    #[brw(pad_before(2))]
    bad: BadBlockIndicator,
    #[brw(pad_before(2))]
    second: Ecc,
    #[brw(pad_before(2))]
    first: Ecc,
}

#[derive(Debug, Clone, Copy)]
pub struct SpareData {
    pub sa_block: u8,
    pub bad: bool,
    pub first: Ecc,
    pub second: Ecc,
}

impl From<SpareBlock> for SpareData {
    fn from(spare: SpareBlock) -> Self {
        let sa_block = if spare.sa_block_data.0 != spare.sa_block_data.1 {
            spare.sa_block_data.2
        } else {
            spare.sa_block_data.0
        };
        let bad = matches!(spare.bad, BadBlockIndicator::Bad(_));
        Self {
            sa_block,
            bad,
            first: spare.first,
            second: spare.second,
        }
    }
}

impl SpareData {
    pub fn export(&self) -> [u8; 0x10] {
        [
            self.sa_block,
            self.sa_block,
            self.sa_block,
            0xFF,
            0xFF,
            0xFF,
            0x00,
            0xFF,
            self.second.0,
            self.second.1,
            self.second.2,
            0xFF,
            0xFF,
            self.first.0,
            self.first.1,
            self.first.2,
        ]
    }
}

#[derive(Debug)]
pub struct Spare {
    pub real_page_spares: bool,
    pub page_spares: Vec<SpareData>,
}

#[derive(Debug, Error)]
pub enum SpareError {
    #[error(
        "Invalid spare size (got 0x{0:X} bytes, expected 0x{SPARE_SIZE_64:X}, 0x{SPARE_SIZE_128:X}, 0x{SPARE_SIZE_64_PAGE:X} or 0x{SPARE_SIZE_128_PAGE:X}"
    )]
    InvalidSize(usize),

    #[error(transparent)]
    IOError(#[from] io::Error),

    #[error(transparent)]
    BinrwError(#[from] binrw::Error),
}

impl Spare {
    pub fn new(size: NandSize) -> Self {
        let page_spares = vec![
            SpareData {
                sa_block: 0xFF,
                bad: false,
                first: (0, 0, 0),
                second: (0, 0, 0)
            };
            match size {
                NandSize::Unspecified => unreachable!(),
                NandSize::Double => NUM_SPARES_128,
                NandSize::Single => NUM_SPARES_64,
            }
        ];

        Self {
            real_page_spares: true,
            page_spares,
        }
    }

    pub fn parse<T: AsRef<[u8]>>(file: T) -> Result<Self, SpareError> {
        let file = file.as_ref();

        let len = file.len();
        if len != SPARE_SIZE_64
            && len != SPARE_SIZE_128
            && len != SPARE_SIZE_64_PAGE
            && len != SPARE_SIZE_128_PAGE
        {
            return Err(SpareError::InvalidSize(len));
        }

        let mut cursor = Cursor::new(file);

        let spares: Vec<SpareBlock> = until_eof(&mut cursor, Endian::Big, ())?;
        let spares: Vec<SpareData> = spares.into_iter().map(SpareData::from).collect();

        let mut page_spares = vec![];

        if len == SPARE_SIZE_64 || len == SPARE_SIZE_128 {
            for spare in &spares {
                page_spares.extend(repeat(*spare).take(PAGES_PER_BLOCK));
            }
        } else {
            page_spares.extend(spares);
        }

        Ok(Self {
            real_page_spares: len == SPARE_SIZE_64_PAGE || len == SPARE_SIZE_128_PAGE,
            page_spares,
        })
    }

    pub fn block_spares(&self) -> Vec<SpareData> {
        let mut rv = vec![];

        for block in self.page_spares.chunks_exact(PAGES_PER_BLOCK) {
            rv.push(*block.last().unwrap());
        }

        rv
    }

    pub fn convert_size(&self, size: NandSize) -> Self {
        let mut spares = self.page_spares.clone();
        match (spares.len(), size) {
            (NUM_SPARES_64, NandSize::Single) | (NUM_SPARES_128, NandSize::Double) => {}
            (NUM_SPARES_64, NandSize::Double) => spares.resize(
                NUM_SPARES_128,
                SpareData {
                    sa_block: 0xFF,
                    bad: false,
                    first: (0, 0, 0),
                    second: (0, 0, 0),
                },
            ),
            (NUM_SPARES_128, NandSize::Single) => spares.truncate(NUM_SPARES_64),
            _ => unreachable!(),
        }

        Self {
            real_page_spares: self.real_page_spares,
            page_spares: spares,
        }
    }

    pub fn write_page_spares(&mut self, address: usize, block: usize) {
        for page in block * PAGES_PER_BLOCK..(block + 1) * PAGES_PER_BLOCK {
            self.page_spares[page].sa_block = address as _;
        }
    }

    pub fn set_page_ecc(&mut self, page: usize, first: Ecc, second: Ecc) {
        self.page_spares[page].first = first;
        self.page_spares[page].second = second;
    }

    pub fn export(&self, full: bool) -> Vec<u8> {
        let mut rv = vec![];

        for block in self.page_spares.chunks_exact(PAGES_PER_BLOCK) {
            if full {
                for page in block {
                    rv.extend(page.export());
                }
            } else {
                rv.extend(block.last().unwrap().export());
            }
        }

        rv
    }
}

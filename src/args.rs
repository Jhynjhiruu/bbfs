use anyhow::Result;
use bbfs::NandSize;
use clap::Parser;

use std::ffi::OsString;
use std::fmt::{self, Display, Formatter};
use std::fs::{read, read_to_string, write};
use std::io::{stdout, Error, ErrorKind, Read, Write};
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub enum IOType {
    Stdin,
    Stdout,
    File(PathBuf),
}

impl IOType {
    pub fn read(&self) -> Result<Vec<u8>, Error> {
        match self {
            Self::Stdin => {
                let mut rv = vec![];
                std::io::stdin().lock().read_to_end(&mut rv)?;
                Ok(rv)
            }
            Self::Stdout => Err(Error::from(ErrorKind::Unsupported)),
            Self::File(path) => read(path),
        }
        .map_err(|e| Error::new(e.kind(), format!("{} ({})", e, self)))
    }

    pub fn read_string(&self) -> Result<String, Error> {
        match self {
            Self::Stdin => {
                let mut rv = String::new();
                std::io::stdin().lock().read_to_string(&mut rv)?;
                Ok(rv)
            }
            Self::Stdout => Err(Error::from(ErrorKind::Unsupported)),
            Self::File(path) => read_to_string(path),
        }
        .map_err(|e| Error::new(e.kind(), format!("{} ({})", e, self)))
    }

    pub fn write<T: AsRef<[u8]>>(&self, data: T) -> Result<usize, Error> {
        match self {
            Self::Stdin => Err(Error::from(ErrorKind::Unsupported)),
            Self::Stdout => stdout().write(data.as_ref()),
            Self::File(path) => write(path, &data).and(Ok(data.as_ref().len())),
        }
    }

    fn input<T: AsRef<str>>(path: T) -> Self {
        match path.as_ref() {
            "-" => Self::Stdin,
            p => Self::File(PathBuf::from(p)),
        }
    }

    fn output<T: AsRef<str>>(path: T) -> Self {
        match path.as_ref() {
            "-" => Self::Stdout,
            p => Self::File(PathBuf::from(p)),
        }
    }

    fn derive_input<F: FnOnce(&PathBuf) -> PathBuf>(&self, f: F) -> Self {
        match self {
            Self::Stdin => Self::Stdin,
            Self::Stdout => Self::Stdin,
            Self::File(p) => Self::File(f(p)),
        }
    }

    fn derive_output<F: FnOnce(&PathBuf) -> PathBuf>(&self, f: F) -> Self {
        match self {
            Self::Stdin => Self::Stdout,
            Self::Stdout => Self::Stdout,
            Self::File(p) => Self::File(f(p)),
        }
    }
}

impl Display for IOType {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Stdin => "stdin".to_string(),
                Self::Stdout => "stdout".to_string(),
                Self::File(f) => f.display().to_string(),
            }
        )
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Input NAND image
    #[arg(required_unless_present("new"), conflicts_with("new"))]
    infile: Option<String>,

    /// Input spare data
    #[arg(short, long, conflicts_with("new"))]
    spare: Option<String>,

    /// Generate a new NAND image
    #[arg(
        short,
        long,
        requires("update"),
        requires("force_128"),
        requires("force_64")
    )]
    new: bool,

    /// Output NAND image
    #[arg(short, long)]
    outfile: Option<String>,

    /// Extract all files from NAND to folder
    #[arg(short('x'), long)]
    extract: Option<String>,

    /// Extract the SKSA blob from NAND to path
    #[arg(short('k'), long, requires("spare"))]
    extract_kernel: Option<String>,

    /// Add file to NAND (may be used multiple times)
    #[arg(short, long)]
    add: Vec<PathBuf>,

    /// Delete file from NAND (may be used multiple times)
    ///
    /// Deletions happen before additions
    #[arg(short, long)]
    delete: Vec<String>,

    /// Update SKSA (use --gen-spare to generate new spare data)
    #[arg(short, long, requires("spare"))]
    update: Option<String>,

    /// Generate spare data for the output NAND image
    /// (or what the output NAND image would be, if no
    /// output options are enabled) to the provided path
    #[arg(short, long, requires("spare"))]
    gen_spare: Option<String>,

    /// Generate page spare instead of block spare
    /// (generally only needed for hardware NAND writers)
    #[arg(short, long, requires("gen_spare"))]
    full_spare: bool,

    /// Force output NAND to 128MiB, instead of copying from input NAND
    #[arg(long)]
    force_128: bool,

    /// Force output NAND to 64MiB, instead of copying from input NAND
    #[arg(long, conflicts_with("force_128"))]
    force_64: bool,

    /// Don't wipe files with invalid chains
    #[arg(short, long)]
    ignore_invalid: bool,
}

#[derive(Debug)]
pub struct Args {
    pub infile: Option<IOType>,
    pub spare: Option<IOType>,
    pub new: bool,
    pub outfile: Option<IOType>,
    pub extract: Option<PathBuf>,
    pub extract_kernel: Option<IOType>,
    pub add: Vec<PathBuf>,
    pub delete: Vec<String>,
    pub update: Option<IOType>,
    pub gen_spare: Option<IOType>,
    pub full_spare: bool,
    pub out_size: NandSize,
    pub ignore_invalid: bool,
}

impl From<Cli> for Args {
    fn from(value: Cli) -> Self {
        fn replace_extension_or(orig: &Path, replace: &[&str], with: &str) -> PathBuf {
            match orig.extension() {
                Some(_)
                    if replace.iter().map(OsString::from).any(|s| {
                        s.to_ascii_lowercase() == orig.extension().unwrap().to_ascii_lowercase()
                    }) =>
                {
                    orig.with_extension(with)
                }
                None => orig.with_extension(with),
                _ => {
                    let mut s = orig.as_os_str().to_owned();
                    s.push(format!(".{with}"));
                    s.into()
                }
            }
        }

        let infile = value.infile.map(IOType::input);
        let spare = value.spare.map(IOType::input);
        let new = value.new;
        let outfile = value.outfile.map(IOType::output);
        let extract = value.extract.map(PathBuf::from);
        let extract_kernel = value.extract_kernel.map(IOType::output);
        let add = value.add;
        let delete = value.delete;
        let update = value.update.map(IOType::input);
        let gen_spare = value.gen_spare.map(IOType::output);
        let full_spare = value.full_spare;

        let out_size = match (value.force_128, value.force_64) {
            (false, false) => NandSize::Unspecified,
            (true, false) => NandSize::Double,
            (false, true) => NandSize::Single,
            _ => unreachable!(),
        };

        let ignore_invalid = value.ignore_invalid;

        Self {
            infile,
            spare,
            new,
            outfile,
            extract,
            extract_kernel,
            add,
            delete,
            update,
            gen_spare,
            full_spare,
            out_size,
            ignore_invalid,
        }
    }
}

pub fn parse_args() -> Args {
    Cli::parse().into()
}

use std::fs::{create_dir_all, write};

use anyhow::Result;
use bbfs::{Nand, NandSize, Spare, NAND_SIZE_64};

mod args;

fn main() -> Result<()> {
    let arguments = args::parse_args();

    let input_spare = arguments
        .spare
        .map(|s| {
            let spare = s.read()?;
            Spare::parse(spare)
        })
        .transpose()?;

    let (mut working_nand, orig_size) = if arguments.new {
        (Nand::new(), NandSize::Unspecified)
    } else {
        let infile = arguments
            .infile
            .expect("impossible argument combination")
            .read()?;

        (
            Nand::parse(&infile, &input_spare)?,
            if infile.len() == NAND_SIZE_64 {
                NandSize::Single
            } else {
                NandSize::Double
            },
        )
    };

    if let Some(path) = arguments.extract {
        create_dir_all(&path)?;
        for ((name, ext), data, valid) in &working_nand.files {
            write(
                path.join(
                    format!("{}{}{}", name, if ext.is_empty() { "" } else { "." }, ext)
                        + if *valid || arguments.ignore_invalid {
                            ""
                        } else {
                            " MAYBE INVALID"
                        },
                ),
                data,
            )?;
        }
    }

    if let Some(path) = arguments.extract_kernel {
        path.write(&working_nand.sksa)?;
    }

    for file in &arguments.delete {
        working_nand.delete_file(file)?;
    }

    for file in &arguments.add {
        working_nand.add_file(file)?;
    }

    if let Some(sksa) = arguments.update {
        let sksa = sksa.read()?;
        working_nand.update_sksa(sksa);
    }

    let output_size = match arguments.out_size {
        NandSize::Unspecified => orig_size,
        NandSize::Double => NandSize::Double,
        NandSize::Single => NandSize::Single,
    };

    let (updated_nand, full_spare) =
        working_nand.export(output_size, &input_spare, arguments.ignore_invalid)?;

    if let Some(outfile) = arguments.outfile {
        outfile.write(updated_nand)?;
    }

    if let Some(spare) = arguments.gen_spare {
        spare.write(full_spare.export(arguments.full_spare))?;
    }

    Ok(())
}

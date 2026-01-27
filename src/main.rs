use serde::{Serialize, Deserialize};
use std::{fs, io::{self}, process, u8};
use serde_json::{from_str, to_string_pretty};
use clap::Parser;
use chacha20poly1305::{
    ChaCha20Poly1305, ChaChaPoly1305, Key, Nonce, aead::{Aead, AeadCore, KeyInit, OsRng}
};
use argon2::{self, Argon2, password_hash::{rand_core::RngCore}};

#[derive(Serialize, Deserialize, Debug)]
struct Entry {
    service: String,
    login: String,
    password: String,
}

#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}


#[derive(Parser)]
enum Commands {
    /// Add an entry of service (-s), login (-l) and password (-p) specified.
    Add {
        #[arg(short)]
        service: String,
        #[arg(short)]
        login: String,
        #[arg(short)]
        password: String,
    },
    /// Delete the entry of the service specified.
    Remove{
        service: String
    },
    /// List every entry.
    List,
}

fn main() {
    
    let data = fs::read("data/data.json").expect("error");
    let mut password = String::new();
    let mut salt = [0u8; 16]; // array de 16 bytes

    if data.is_empty() {
        OsRng.fill_bytes(&mut salt); // on remplit salt
    } else {
        let file_data = fs::read("data/data.json").expect("error"); 
        let (s, _) = file_data.split_at(16);
        salt.copy_from_slice(s); // on copie les 16 bytes dans salt
    }

    if data.is_empty() {
        println!("Please, choose your password.");
        
        let mut confirmation = String::new();
        
        io::stdin().read_line(&mut password).expect("Not a good pwd");
        println!("Confirm your password.");
        io::stdin().read_line(&mut confirmation).expect("Not the same password");
        
        if confirmation != password {
            println!("Password aren't the same!");
            process::abort();
        }
    } else {
        println!("Please, type your password.");
        io::stdin().read_line(&mut password).expect("Not a good pwd");
    }

    let key = derive_key(&password, &salt);
    let cipher = ChaChaPoly1305::new(&key);

    let mut entries =
        if data.is_empty() {
            Vec::new()
        } else {
            decrypt(&data.to_vec(), &cipher)
        };

       
    let cli = Cli::parse();
    match cli.command {
        Commands::Add { service, login, password } => {
            // Add the entry that the user wrote to the vector
            entries.push(Entry{ service, login, password});

            let mut encrypted = Vec::new();
            encrypted.extend_from_slice(&salt);
            encrypted.extend_from_slice(&encrypt(&entries, &cipher)); 
           
            fs::write("data/data.json", encrypted).expect("6");
        }

        Commands::Remove { service } => {
            // Keep every entry where the service doesn't correspond to the one that the user want to remove
            entries.retain(|entry| entry.service != service);

            let mut encrypted = Vec::new();
            encrypted.extend_from_slice(&salt);
            encrypted.extend_from_slice(&encrypt(&entries, &cipher)); 

            fs::write("data/data.json", encrypted).expect("6");
        }

        Commands::List => {
            // Print the vector
            println!("{:#?}", entries);
        }
    }
}

fn encrypt(entries: &Vec<Entry>, cipher: &ChaCha20Poly1305) -> Vec<u8> {
    let e_nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng); // 96-bits; unique per message

    // Rewrote the vector with the value added to the data file
    let json = to_string_pretty(&entries).expect("4");
            
    let encrypted = cipher.encrypt(&e_nonce, json.as_bytes()).expect("Wrong password!");

    let mut out = Vec::new();
    out.extend_from_slice(&e_nonce);
    out.extend_from_slice(&encrypted);
    out
}


fn decrypt(data: &Vec<u8>, cipher: &ChaCha20Poly1305) -> Vec<Entry> {
    let (d_nonce_bytes, ciphertext) = data.split_at(12);
    let d_nonce = Nonce::from_slice(d_nonce_bytes);
                
    let decrypted = cipher.decrypt(&d_nonce, ciphertext).expect("Wrong password!"); 
    let json = String::from_utf8(decrypted).expect("2"); 
    from_str::<Vec<Entry>>(&json).expect("3")
}

fn derive_key(pwd: &str, salt: &[u8]) -> Key {
    // ChaCha20Poly1305 demands a 256 bits key -> 32 bytes
    let mut key_bytes = [0u8; 32];

    Argon2::default().hash_password_into(
        pwd.as_bytes(),
        salt,
        &mut key_bytes).expect("");

    Key::from_slice(&key_bytes).clone()
}

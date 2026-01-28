use rpassword::{prompt_password};
use serde::{Deserialize, Serialize};
use std::{error::Error, fs, path::PathBuf, process, u8};
use dirs;
use serde_json::{from_str, to_string_pretty};
use clap::Parser;
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce, aead::{Aead, AeadCore, KeyInit, OsRng}
};
use argon2::{self, Argon2, password_hash::rand_core::{RngCore}};

const SALT_SIZE_BYTES: usize = 16;
const NONCE_SIZE_BYTES: usize = 12;

const TYPE_PWD:&str = "Type your 'passmngr' password:";
const CHOOSE_PWD:&str = "Choose your 'passmngr' password:";
const WRONG_PWD:&str = "Wrong password!";
const PWD_CONFIRMATION:&str = "Confirm your 'passmngr' password:";
const PWD_NOT_CORRESPOND:&str = "You wrote two different password.";
const EMPTY_DATA:&str = "You have no entry in your list yet!"; 
const NO_SERVICE:&str = "No service corresponding.";
const EXIST_ALREADY:&str = "The service already exist, please remove the old entry to add a new one.";

const PATH_1:&str = "passmngr";
const PATH_2:&str = "data.bin";
const CREATE_PATH_FAIL:&str = "Impossible to create the path.";
const FAIL: &str = "Argon2 failed";

#[derive(Serialize, Deserialize)]
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
enum Commands{
    /// Add an entry of service (-s), login (-l) and password specified.
    Add {
        #[arg(short)]
        service: String,
        #[arg(short)]
        login: String,
    },
    /// Delete the entry of the service specified.
    Remove{
        service: String
    },
    /// Show the login and the password of the service asked by the user.
    Info {
        service: String  
    },
    /// List every entry.
    List,
    /// Change your password.
    Passwd,
}

fn main() -> Result<(), Box<dyn Error>>{

    let data_file = get_data_path();
    let data =
        if !data_file.exists() {
            Vec::new()
        } else {
            fs::read(&data_file)?
        };

    let mut salt = [0u8; SALT_SIZE_BYTES];

    let password =
    // If there is no data yet => 
    // 1. Init the salt
    // 2. Ask the user to create a password and to confirm
        if data.is_empty() {
            OsRng.fill_bytes(&mut salt);
         
            let pwd = prompt_password(CHOOSE_PWD)?;
            let confirmation = prompt_password(PWD_CONFIRMATION)?;
    
            if confirmation != pwd {
                println!("{}", PWD_NOT_CORRESPOND);
                process::abort();
            }
            pwd
        // If there is some data already =>
        // Extract the salt and the password from the data
        } else {
            let file_data = fs::read(&data_file)?; 
            // Keep only the part of data that contains the salt
            let (s, _) = file_data.split_at(SALT_SIZE_BYTES);
            salt.copy_from_slice(s);
    
            prompt_password(TYPE_PWD)?
        };

    let key = derive_key(&password, &salt);
    let cipher = ChaCha20Poly1305::new(&key);
 
    // If there is no data yet, init entries as an empty vec,
    // otherwise init entries as the old entries decrypted
    let mut entries =
        if data.is_empty() {
            Vec::new()
        } else {
            // Keep only the part of data that contains the nonce and entries encrypted
            let (_, data) = data.split_at(SALT_SIZE_BYTES);
            decrypt(&data.to_vec(), &cipher)?
        };

    let cli = Cli::parse();
    match cli.command {
        Commands::Add { service, login } => {
            
            if entries.iter().any(|entry| entry.service == service) {
                println!("{}",EXIST_ALREADY);
                process::abort();
            }

            let pwd = prompt_password(&format!("Write the password of your {} account:", service))?;
            // Add the entry that the user wrote to the vector
            entries.push(Entry{ service, login, password: pwd});

            // Prepare encrypted, that contains the salt, the nonce and entries encrypted
            let mut encrypted = Vec::new();
            encrypted.extend_from_slice(&salt);
            encrypted.extend_from_slice(&encrypt(&entries, &cipher)?); 
           
            fs::write(&data_file, encrypted)?;
            Ok(())
        }

        Commands::Remove { service } => {

            if !entries.iter().any(|entry| entry.service == service) {
                println!("{}", NO_SERVICE);
                process::abort();
            }
            
            // Keep every entry where the service doesn't correspond to the one that the user want to remove
            entries.retain(|entry| entry.service != service);

            // Prepare encrypted, that contains the salt, the nonce and entries encrypted
            let mut encrypted = Vec::new();
            encrypted.extend_from_slice(&salt);
            encrypted.extend_from_slice(&encrypt(&entries, &cipher)?); 

            fs::write(&data_file, encrypted)?;
            Ok(())
        }

        Commands::Info { service } => {
            entries.retain(|entry| entry.service == service);
            let entry = entries.first().expect(NO_SERVICE);
            println!("The login of '{}' is '{}', and the password is '{}'.", service, entry.login, entry.password);
            Ok(())
        }

        Commands::List => {
            if data.is_empty() {
                println!("{}", EMPTY_DATA);
                process::abort();
            }
            // Print the vector
            let mut i = 0;
            for entry in entries {
                println!("{i}.");
                println!("  -Service: {}", entry.service);
                println!("  -Login: {}", entry.login);
                println!("  -Password: {}", entry.password);
                i += 1;
            }
            Ok(())
        }

        Commands::Passwd => {
            
            // If the data is empty, impossible to change the password
            if data.is_empty() {
                println!( "{}", EMPTY_DATA);
                process::abort();
            }
            
            let new_pwd = prompt_password(CHOOSE_PWD)?;
            let confirmation = prompt_password(PWD_CONFIRMATION)?;
 
            if confirmation != new_pwd {
                println!("{}", PWD_NOT_CORRESPOND);
                process::abort();
            }

            // Create a new salt, and then derive the key with the new pwd and the new salt
            OsRng.fill_bytes(&mut salt);

            let key = derive_key(&new_pwd, &salt);
            let cipher = ChaCha20Poly1305::new(&key);

            // Encrypt the data with our new salt
            let mut encrypted = Vec::new();
            encrypted.extend_from_slice(&salt);
            encrypted.extend_from_slice(&encrypt(&entries, &cipher)?); 

            fs::write(data_file, encrypted)?;

            Ok(())
        }
    }
}

fn encrypt(entries: &Vec<Entry>, cipher: &ChaCha20Poly1305) -> Result<Vec<u8>, Box<dyn Error>> {
    // Generate the nonce (12 bytes)
    let e_nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng); 

    let json = to_string_pretty(&entries)?;
    let encrypted = cipher.encrypt(&e_nonce, json.as_bytes()).expect(WRONG_PWD);

    // Return a byte vector that contains the nonce and then the entries encrypted
    let mut out = Vec::new();
    out.extend_from_slice(&e_nonce);
    out.extend_from_slice(&encrypted);
    Ok(out)
}

fn decrypt(data: &Vec<u8>, cipher: &ChaCha20Poly1305) -> Result<Vec<Entry>, Box<dyn Error>> {
    // Extract the nonce (type byte for the moment) and the crypted entries from the data
    let (d_nonce_bytes, ciphertext) = data.split_at(NONCE_SIZE_BYTES);
    let d_nonce = Nonce::from_slice(d_nonce_bytes);
                
    let decrypted = cipher.decrypt(&d_nonce, ciphertext).expect(WRONG_PWD); 
    let json = String::from_utf8(decrypted)?; 
    Ok(from_str::<Vec<Entry>>(&json)?)
}

fn derive_key(pwd: &str, salt: &[u8]) -> Key {
    // ChaCha20Poly1305 demands a 256 bits key -> 32 bytes
    let mut key_bytes = [0u8; 32];

    // Create a byte array with the password and the salt
    Argon2::default().hash_password_into(
        pwd.as_bytes(),
        salt,
        &mut key_bytes).expect(FAIL);

    Key::from_slice(&key_bytes).clone()
}

// Function that create the path to a passmngr folder in the .config folder of the user,
// and then create the path to a data.bin file inside. 
fn get_data_path() -> PathBuf {
    let mut path = dirs::config_dir().expect(CREATE_PATH_FAIL);
    path.push(PATH_1); 
    std::fs::create_dir_all(&path).expect(CREATE_PATH_FAIL);
    path.push(PATH_2);
    path
}

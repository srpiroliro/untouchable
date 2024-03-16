use rsa::pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPrivateKey, EncodeRsaPublicKey};
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use rand::rngs::OsRng;

use std::error::Error;
use base64::prelude::*;

use std::time::Instant;

const KEY_SIZE:usize = 4096;

#[derive(Debug)]
struct Identity {
    name: String,
    private_key: Option<RsaPrivateKey>,
    public_key: RsaPublicKey,
}
impl Identity {
    fn new(name:&str) -> Self {
        let (private_key, public_key) = Identity::generate_keys();
        
        Identity {
            name: name.to_string(),
            private_key: Some(private_key),
            public_key
        }
    }

    fn load(name:&str) -> Result<Self, Box<dyn std::error::Error>> {
        let fullpath:String = "identities/".to_owned() + name + ".key";

        let private_pem = std::fs::read_to_string(&fullpath)?;
        let public_pem = std::fs::read_to_string(fullpath+".pub").unwrap();

        let public_key = RsaPublicKey::from_pkcs1_pem(&public_pem)?;
        let private_key = RsaPrivateKey::from_pkcs1_pem(&private_pem)?;

        Ok(Identity {
            name: name.to_string(),
            private_key: Some(private_key),
            public_key,
        })
    } 

    fn generate_keys() -> (RsaPrivateKey, RsaPublicKey) {
        let mut rng = OsRng;
 
        let private_key = RsaPrivateKey::new(&mut rng, KEY_SIZE).expect("failed to generate a key");
        let public_key = RsaPublicKey::from(&private_key);

        (private_key,public_key)
    }

    ////////   ////////   ////////   ////////
    
    fn get_public_key(&self) -> &RsaPublicKey {
        &self.public_key
    }

    fn encrypt(&self, destination: &Identity, message: &str) -> Result<String, Box<dyn Error>> {
        let mut rng = rand::thread_rng();
        let byted_data = message.as_bytes();

        assert!(byted_data.len() <= (KEY_SIZE/8 - 11));

        let destination_key = destination.get_public_key();
        let encrypted_data = destination_key
            .encrypt(&mut rng, Pkcs1v15Encrypt, &byted_data[..])
            .expect("failed to encypt");
        
        let base64_str = BASE64_STANDARD.encode(&encrypted_data);

        Ok(base64_str)
    }

    fn decrypt(&self, secret: String) -> Result<String, Box<dyn Error>> {
        let encrypted_message = BASE64_STANDARD.decode(&secret)?;

        if let Some(key) = &self.private_key {
            let decrypted_data = key.decrypt(Pkcs1v15Encrypt, &encrypted_message[..])?;
            let result = std::str::from_utf8(&decrypted_data)?;
    
            Ok(result.to_owned())
        } else {
            panic!("no private key")
        }

    }

    fn save(&self, filename: &str) {
        let fullpath:String = "identities/".to_owned() + filename + ".key";

        if let Some(key) = &self.private_key {
            key.write_pkcs1_pem_file(
                &fullpath, 
                rsa::pkcs8::LineEnding::LF)
            .unwrap();
        }

        self.public_key
            .write_pkcs1_pem_file(
                fullpath+".pub", 
                rsa::pkcs8::LineEnding::LF)
            .unwrap();
    }
} 


fn main() -> Result<(), Box<dyn Error>>{
    let ident = Identity::load("test")?;
    let ident2 = Identity::new("");

    let testing = "hello hellow ! asasd21343Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book";

    let e = ident.encrypt(&ident2, testing)?;
    let d = ident2.decrypt(e.clone())?;

    assert_eq!(testing,d);

    Ok(())
}

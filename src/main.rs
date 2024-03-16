use rsa::pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPrivateKey, EncodeRsaPublicKey};
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use rsa::traits::PaddingScheme;
use rand::rngs::OsRng;
use serde_json;

use std::error::Error;
use base64::prelude::*;

#[derive(Debug)]
struct Identity {
    name: String,
    keys: KeyPair
}
impl Identity {
    fn new(name:&str) -> Self {
        Identity {
            name: name.to_string(),
            keys: KeyPair::new(),
        }
    }

    fn load(name:&str) -> Result<Self, Box<dyn std::error::Error>> {
        let loaded_keys = KeyPair::load(&name)?;

        Ok(Identity {
            name: name.to_string(),
            keys: loaded_keys,
        })
    }

    fn save(&self) {
        self.keys.save(&self.name);
    }


    ////////
    

    fn encrypt(&self, message: String) -> Result<String, Box<dyn Error>> {
        let result = self.keys.encrypt(message)?;

        Ok(result)
    }

    fn decrypt(&self, secret: String) -> Result<String, Box<dyn Error>> {
        let result = self.keys.decrypt(secret)?;

        Ok(result)
    }

} 


#[derive(Debug)]
struct KeyPair {
    private_key: RsaPrivateKey,
    public_key: RsaPublicKey,
    size: usize,
}

impl KeyPair {
    fn new() -> Self {
        let mut rng = OsRng;
        let bits:usize = 4096;
        let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
        let public_key = RsaPublicKey::from(&private_key);

        KeyPair {
            private_key,
            public_key,
            size: bits
        }
    }

    fn save(&self, filename: &str) {
        let fullpath:String = "identities/".to_owned() + filename + ".key";

        self.private_key
            .write_pkcs1_pem_file(
                &fullpath, 
                rsa::pkcs8::LineEnding::LF)
            .unwrap();

        self.public_key.write_pkcs1_pem_file(
                fullpath+".pub", 
                rsa::pkcs8::LineEnding::LF)
            .unwrap();
    }
    
    fn load(filename: &str) -> Result<Self, Box<dyn Error>>{
        let fullpath:String = "identities/".to_owned() + filename + ".key";

        let private_pem = std::fs::read_to_string(&fullpath)?;
        let public_pem = std::fs::read_to_string(fullpath+".pub").unwrap();

        let public_key = RsaPublicKey::from_pkcs1_pem(&public_pem)?;
        let private_key = RsaPrivateKey::from_pkcs1_pem(&private_pem)?;

        Ok(KeyPair {
                private_key,
                public_key,
                size: 4096
            })
    }

    fn encrypt(&self, message:String) -> Result<String, Box<dyn Error>> {
        let mut rng = rand::thread_rng();
        let byted_data = message.as_bytes();

        assert!(byted_data.len() <= (self.size/8 - 11));

        let encrypted_data = self.public_key.encrypt(&mut rng, Pkcs1v15Encrypt, &byted_data[..]).expect("failed to encypt");
        
        let base64_str = BASE64_STANDARD.encode(&encrypted_data);

        Ok(base64_str)
    }

    fn decrypt(&self, base64_encrypted_message: String) -> Result<String, Box<dyn Error>> {
        let encrypted_message = BASE64_STANDARD.decode(&base64_encrypted_message)?;

        let decrypted_data = self.private_key
            .decrypt(Pkcs1v15Encrypt, &encrypted_message[..])?;

        let result = std::str::from_utf8(&decrypted_data)?;

        Ok(result.to_owned())
    }

}


fn main() -> Result<(), Box<dyn Error>>{
    let ident = Identity::new("test");

    let testing = "hello hellow ! asasd21343Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book";

    let e = ident.encrypt(testing.to_owned())?;
    let d = ident.decrypt(e.clone())?;

    assert_eq!(testing,d);

    Ok(())
}

use rsa::pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPrivateKey, EncodeRsaPublicKey};
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use rsa::traits::PaddingScheme;
use rand::rngs::OsRng;
use serde_json;

use std::error::Error;


#[derive(Debug)]
struct Identity {
    name: String,
    keys: KeyPair
}
impl Identity {
    fn new(name:String) -> Self {
        Identity {
            name,
            keys: KeyPair::new(),
        }
    }

    fn load(name:String) -> Result<Self, Box<dyn std::error::Error>> {
        let loaded_keys = KeyPair::load(&name)?;

        Ok(Identity {
            name,
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
}

impl KeyPair {
    fn new() -> Self {
        let mut rng = OsRng;
        let bits = 2048;
        let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
        let public_key = RsaPublicKey::from(&private_key);

        KeyPair {
            private_key,
            public_key,
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
                public_key
            })
    }

    fn encrypt(&self, message:String) -> Result<String, Box<dyn Error>> {
        let mut rng = rand::thread_rng();
        let encrypted_data = self.public_key.encrypt(&mut rng, Pkcs1v15Encrypt, message.as_bytes()).expect("failed to encypt");
        
        let str_data = String::from_utf8_lossy(&encrypted_data).to_string();

        Ok(str_data)
    }

    fn decrypt(&self, encrypted_message: String) -> Result<String, Box<dyn Error>> {
        let decrypted_data = self.private_key.decrypt(Pkcs1v15Encrypt, encrypted_message.as_bytes()).expect("failed to decrypt");
        let str_data = String::from_utf8_lossy(&decrypted_data).to_string();

        Ok(str_data)
    }

}


fn main() -> Result<(), Box<dyn Error>>{
    let ident = Identity::load("test".to_owned())?;

    let testing = "hello hellow ! asasd21343";

    let e = ident.encrypt(testing.to_owned())?;
    let d = "a";// ident.decrypt(e.clone())?;

    println!("enc: {:?} // dec: {:?}", e, d);


    Ok(())
}

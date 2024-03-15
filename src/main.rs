use rsa::pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPrivateKey, EncodeRsaPublicKey};
use rsa::{RsaPrivateKey, RsaPublicKey};
use rsa::traits::PaddingScheme;
use rand::rngs::OsRng;
use serde_json;


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
    
    fn load(filename: &str) -> Result<Self, Box<dyn std::error::Error>>{
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

}


fn main() {




    let ide = Identity::load("tesasdst".to_owned());

    println!("{:?}", ide);
}

// fn save_keys(keypair:KeyPair, filepath: &str) {
//     let private_key_str = keypair.
// }

// fn load_keys(filepath: &str) -> KeyPair {


//     ("","")
// } 
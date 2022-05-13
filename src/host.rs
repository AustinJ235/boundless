use std::fs::File;
use std::io::{Read, Write};
use std::fs::create_dir;
use std::path::PathBuf;
use serde::{Serialize, Deserialize};
use blake3::{hash, Hash};
use k256::ecdsa::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use std::collections::HashMap;

pub struct HostInfo {
    id: Hash,
    private_key: SigningKey,
    trusted_remote_hosts: HashMap<Hash, RemoteHostInfo>,
}

struct RemoteHostInfo {
    id: Hash,
    public_key: VerifyingKey,
}

#[derive(Serialize, Deserialize)]
struct ConfigFile {
    private_key: String,
    trusted_public_keys: Vec<String>,
}

impl HostInfo {
    pub fn data_file() -> Result<PathBuf, String> {
        let mut path = dirs::data_local_dir()
            .ok_or(String::from("Data local direction unavailable on platform."))?;
        path.push("boundless");

        if !path.exists() {
            create_dir(&path)
                .map_err(|e| format!("Data directory doesn't exist. Unable to create directory: {}", e.kind()))?;
        }

        path.push("config.json");
        Ok(path)
    }

    pub fn load() -> Result<Self, String> {
        let mut handle = File::options()
            .read(true)
            .open(Self::data_file()?)
            .map_err(|e| format!("Unable to open config.json: {}", e.kind()))?;
        let mut data = String::new();
        handle.read_to_string(&mut data)
            .map_err(|e| format!("Unable to read config.json: {}", e.kind()))?;
        let config: ConfigFile = serde_json::from_str(&data)
            .map_err(|e| format!("Unable to parse config.json: {}", e))?;
        let private_key_bytes: Vec<u8> = base64::decode(&config.private_key)
            .map_err(|_| format!("Unable to parse config.json: Invalid private key"))?;
        let private_key = SigningKey::from_bytes(&private_key_bytes)
            .map_err(|_| format!("Unable to parse config.json: Invalid private key"))?;
        let host_id = hash(private_key.verifying_key().to_bytes().as_slice());

        let mut host_info = Self {
            id: host_id,
            private_key,
            trusted_remote_hosts: HashMap::new()
        };

        for (i, pk_string) in config.trusted_public_keys.into_iter().enumerate() {
            let pk_bytes: Vec<u8> = base64::decode(&pk_string)
                .map_err(|_| format!("Unable to parse config.json: Public key #{} is invalid", i + 1))?;
            let public_key = VerifyingKey::from_sec1_bytes(&pk_bytes)
                .map_err(|_| format!("Unable to parse config.json: Public key #{} is invalid", i + 1))?;
            let remote_id = hash(&pk_bytes);

            host_info.trusted_remote_hosts.insert(remote_id.clone(), RemoteHostInfo {
                id: remote_id,
                public_key
            });
        }

        Ok(host_info)
    }

    pub fn generate() -> Self {
        let private_key = SigningKey::random(&mut OsRng);
        let id = hash(private_key.verifying_key().to_bytes().as_slice());

        Self {
            id,
            private_key,
            trusted_remote_hosts: HashMap::new(),
        }
    }

    pub fn save(&self) -> Result<(), String> {
        let private_key = base64::encode(&self.private_key.to_bytes().as_slice());
        let mut trusted_public_keys = Vec::new();

        for remote_host in self.trusted_remote_hosts.values() {
            trusted_public_keys.push(base64::encode(remote_host.public_key.to_bytes().as_slice()));
        }

        let config = ConfigFile {
            private_key,
            trusted_public_keys
        };

        let mut handle = File::create(Self::data_file()?)
            .map_err(|e| format!("Unable to create config.json: {}", e.kind()))?;
        serde_json::to_writer_pretty(&mut handle, &config)
            .map_err(|e| format!("Failed to write config.json: {}", e))?;
        Ok(())
    }

    pub fn id(&self) -> Hash {
        self.id.clone()
    }

    pub fn public_key(&self) -> VerifyingKey {
        self.private_key.verifying_key()
    }

    pub fn enc_public_key(&self) -> String {
        base64::encode(self.public_key().to_bytes().as_slice())
    }

    pub fn is_host_trusted(&self, id: Hash) -> bool {
        if self.id == id {
            true
        } else {
            self.trusted_remote_hosts.contains_key(&id)
        }
    }

    pub fn public_key_of(&self, id: Hash) -> Option<VerifyingKey> {
        if self.id == id {
            Some(self.public_key())
        } else {
            self.trusted_remote_hosts.get(&id).map(|rh| rh.public_key.clone())
        }
    }

    pub fn enc_public_key_of(&self, id: Hash) -> Option<String> {
        if self.id == id {
            Some(self.enc_public_key())
        } else {
            self.trusted_remote_hosts.get(&id).map(|rh| base64::encode(rh.public_key.to_bytes().as_slice()))
        }
    }

    pub fn trust(&mut self, enc_public_key: String) -> Result<(), String> {
        let pk_bytes: Vec<u8> = base64::decode(&enc_public_key)
            .map_err(|_| format!("Public key is invalid."))?;
        let public_key = VerifyingKey::from_sec1_bytes(&pk_bytes)
            .map_err(|_| format!("Public key is invalid."))?;
        let remote_id = hash(&pk_bytes);

        self.trusted_remote_hosts.insert(remote_id.clone(), RemoteHostInfo {
            id: remote_id,
            public_key
        });

        Ok(())
    }

    pub fn trusted(&self) -> Vec<String> {
        self.trusted_remote_hosts.values().map(|rh| base64::encode(rh.public_key.to_bytes().as_slice())).collect()
    }

    pub fn distrust(&mut self, enc_public_key: String) -> Result<bool, String> {
        let pk_bytes: Vec<u8> = base64::decode(&enc_public_key)
            .map_err(|_| format!("Public key is invalid."))?;
        let public_key = VerifyingKey::from_sec1_bytes(&pk_bytes)
            .map_err(|_| format!("Public key is invalid."))?;
        let remote_id = hash(&pk_bytes);
        Ok(self.trusted_remote_hosts.remove(&remote_id).is_some())
    }
}

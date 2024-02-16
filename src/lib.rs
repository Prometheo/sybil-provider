use std::collections::HashMap;

use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::collections::UnorderedMap;
use near_sdk::env::block_timestamp;
use near_sdk::{env, require, AccountId, PanicOnDefault, PublicKey};
use near_sdk::near_bindgen;
use ed25519_dalek::Verifier;

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, PanicOnDefault)]
pub struct Contract {
  records: UnorderedMap<AccountId, UserData>,
  handles: UnorderedMap<(String, String), AccountId>, // map platform + handle to account_id
  admin_pub: PublicKey
}

#[derive(BorshSerialize, BorshDeserialize)]
struct UserData {
  access_key_count: Option<u32>,
  account_age: Option<u128> ,
  socials: HashMap<String, SocialData> //platform_name -> platform_data
  // other fields
}

#[derive(BorshDeserialize, BorshSerialize, PanicOnDefault)]
pub struct SocialData {
    pub issued_date: u64, 
    pub handle: String,
    pub proof: String,
    pub expiry_date: u64
}


#[near_bindgen]
impl Contract {
    #[init]
    pub fn new(pub_key: PublicKey) -> Self {
        Self {
            records: UnorderedMap::new(b"r".to_vec()),
            handles: UnorderedMap::new(b"h".to_vec()),
            admin_pub: pub_key,
        }
    }

    #[payable]
    pub fn register_social(&mut self, platform: String, signature: Vec<u8>, handle: String, proof: String, max_block_height: u64) {
        
        // basically, need to assert early that handle is not already registered nor has it expired, before other computations.
        require!(max_block_height > env::block_height(), "expired request");
        let account_id = env::signer_account_id();
        let user_dat = self.records.get(&account_id); // get user records
        if user_dat.is_some() { // if record exists, assert that handle is not already registered nor has it expired.
            assert!(!self.handles.get(&(platform.clone(), handle.clone())).is_some() || user_dat.as_ref().unwrap().socials.get(&platform).map_or(false, |x| x.expiry_date < block_timestamp()), "handle already registered");
        }
        let signature = ed25519_dalek::Signature::try_from(signature.as_ref()).expect("invalid SIg.");
        let public_key = ed25519_dalek::PublicKey::from_bytes(&self.admin_pub.as_bytes()[1..]).unwrap();
        let message = account_id.to_string() + "," + platform.as_str() + "," + handle.as_str() + "," + proof.as_str() + "," + max_block_height.to_string().as_str();
        let vfg = public_key.verify(message.as_bytes(), &signature).is_ok();
        assert!(vfg, "unverified data");
        let expiry_date = block_timestamp() + 3 * 30 * 24 * 60 * 60 * 1_000_000_000;// 3 months (make more dynamic later)
        self.handles.insert(&(platform.clone(), handle.clone()), &account_id);
        if let Some( mut user_data) = user_dat {
            if let Some(social_data) = user_data.socials.get(&platform) {
                if social_data.proof == proof {env::panic_str("incorrect proof")};
            }
            let sd = SocialData { issued_date: env::block_timestamp(), handle, proof, expiry_date };
            user_data.socials.insert(platform, sd);
            self.records.insert(&account_id, &user_data);  
        } else {
            let user_data = UserData {
                access_key_count: None,
                account_age: None,
                socials: HashMap::from([
                    (platform, SocialData { issued_date: env::block_timestamp(), handle, proof, expiry_date })
                ])
            };
            self.records.insert(&account_id, &user_data); 
        }
        
    }

    pub fn update_access_key(&mut self, signature: Vec<u8>, account_info: u32, max_block_height: u64) {
        require!(max_block_height > env::block_height(), "expired request"); // assert that request is not expired by block height
        let account_id = env::signer_account_id();
        let signature = ed25519_dalek::Signature::try_from(signature.as_ref()).expect("invalid SIg.");
        let public_key = ed25519_dalek::PublicKey::from_bytes(&self.admin_pub.as_bytes()[1..]).unwrap();
        let message = account_id.to_string() + "," + account_info.to_string().as_str() + "," + max_block_height.to_string().as_str();
        let vfg = public_key.verify(message.as_bytes(), &signature).is_ok();
        assert!(vfg, "unverified data");
        if let Some(mut user_data) = self.records.get(&account_id) {
            user_data.access_key_count = Some(account_info);
            self.records.insert(&account_id, &user_data);  
        } else {
            let user_data = UserData {
                access_key_count: Some(account_info),
                account_age: None,
                socials: HashMap::new()
            };
            self.records.insert(&account_id, &user_data); 
        }
    }


    pub fn update_contract_age(&mut self, signature: Vec<u8>, account_info: u128, max_block_height: u64) {
        require!(max_block_height > env::block_height(), "expired request"); // assert that request is not expired by block height
        let account_id = env::signer_account_id();
        // validate u64 account_age
        
        let signature = ed25519_dalek::Signature::try_from(signature.as_ref()).expect("invalid SIg.");
        let public_key = ed25519_dalek::PublicKey::from_bytes(&self.admin_pub.as_bytes()[1..]).unwrap();
        let message = account_id.to_string() + "," + account_info.to_string().as_str() + "," + max_block_height.to_string().as_str();
        let vfg = public_key.verify(message.as_bytes(), &signature).is_ok();
        assert!(vfg, "unverified data");
        if let Some(mut data) = self.records.get(&account_id) {
            data.account_age = Some(account_info);
            self.records.insert(&account_id, &data);  
        } else {
            let user_data = UserData {
                access_key_count: None,
                account_age: Some(account_info),
                socials: HashMap::new()
            };
            self.records.insert(&account_id, &user_data);
        }
    }

    pub fn connected_to_5_contracts(&self, account_id: AccountId) -> bool {
        if let Some(data) = self.records.get(&account_id) {
            return data.access_key_count.unwrap() >= 5; 
        }
        false
    }

    pub fn connected_to_20_contracts(&self, account_id: AccountId) -> bool {
        if let Some(data) = self.records.get(&account_id) {
            return data.access_key_count.unwrap() >= 20; 
        }
        false
    }

    pub fn connected_to_lens(&self, account_id: AccountId) -> bool {
        if let Some(data) = self.records.get(&account_id) {
            let lens_socials = data.socials.get("lens");
            if lens_socials.is_some() {
                return lens_socials.unwrap().expiry_date > block_timestamp();
            }
        }
        false
    }

    pub fn connected_to_farcaster(&self, account_id: AccountId) -> bool {
        if let Some(data) = self.records.get(&account_id) {
            if data.socials.get("farcaster").is_some() {return true}
        }
        false
    }

    pub fn connected_to_10_contracts(&self, account_id: AccountId) -> bool {
        if let Some(data) = self.records.get(&account_id) {
            return data.access_key_count.unwrap() >= 10; 
        }
        false
    }

    pub fn six_month_old(&self, account_id: AccountId) -> bool {
        if let Some(data) = self.records.get(&account_id) {
            let age_nanoseconds = data.account_age.unwrap();
            let now = block_timestamp();
            let six_months = 6 * 30 * 24 * 60 * 60 * 1_000_000_000;
            return (now - age_nanoseconds as u64) > six_months;

        }
        false
    }

    pub fn connected_to_platform(&self, account_id: AccountId, platform: String) -> bool {
        if let Some(data) = self.records.get(&account_id) {
            return data.socials.get(platform.as_str()).is_some();
        }
        false
    }

    pub fn is_two_year_old(&self, account_id: AccountId) -> bool {
        if let Some(data) = self.records.get(&account_id) {
            let age_nanoseconds = data.account_age.unwrap();
            let now = block_timestamp();
            let two_years = 2 * 365 * 24 * 60 * 60 * 1_000_000_000;
            return (now - age_nanoseconds as u64) >= two_years;
        }
        false
    }

    pub fn is_one_year_old(&self, account_id: AccountId) -> bool {
        if let Some(data) = self.records.get(&account_id) {
            let age_nanoseconds = data.account_age.unwrap();
            let now = block_timestamp();
            let one_year = 365 * 24 * 60 * 60 * 1_000_000_000;
            return (now - age_nanoseconds as u64) >= one_year;
        }
        false
    }

    pub fn is_three_month_old(&self, account_id: AccountId) -> bool {
        if let Some(data) = self.records.get(&account_id) {
            let age_nanoseconds = data.account_age.unwrap();
            let now = block_timestamp();
            let three_months = 3 * 30 * 24 * 60 * 60 * 1_000_000_000;
            return (now - age_nanoseconds as u64) >= three_months;
        }
        false
    }

    pub fn is_a_month_old(&self, account_id: AccountId) -> bool {
        if let Some(data) = self.records.get(&account_id) {
            let age_nanoseconds = data.account_age.unwrap();
            let now = block_timestamp();
            let one_month = 30 * 24 * 60 * 60 * 1_000_000_000; // abstract 30 * 24 * 60 * 60 * 1_000_000_000 to a constant
            return (now - age_nanoseconds as u64) >= one_month;
        }
        false
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use near_sdk::test_utils::{accounts, VMContextBuilder};
    use near_sdk::testing_env;
    use std::str::FromStr;

    use super::*;

    const MINT_STORAGE_COST: u128 = 2385000000000000000000000;

    fn get_context(predecessor_account_id: AccountId) -> VMContextBuilder {
        let mut builder = VMContextBuilder::new();
        builder
            .current_account_id(accounts(0))
            .signer_account_id(predecessor_account_id.clone())
            .predecessor_account_id(predecessor_account_id);
        builder
    }

    #[test]
    fn test_new() {
        let mut context = get_context(accounts(1));
        let receiver = AccountId::new_unchecked("genadop.testnet".to_string());
        testing_env!(context.build());
        testing_env!(context
            .storage_usage(env::storage_usage())
            .attached_deposit(MINT_STORAGE_COST)
            .predecessor_account_id(receiver.clone())
            .signer_account_id(receiver.clone())
            .block_timestamp(2000)
            .build());
        let sig: Vec<u8> = [
            225, 188, 213, 178, 192, 139, 107,  15,  58,  47,  90,
             64, 245,  45, 197, 123, 190,  21, 181,  27, 114, 213,
             34,  40, 211, 221, 112, 189, 130,  75, 175, 141, 127,
            253, 140, 173,  29,   6,  31, 225, 249,  65, 180, 105,
             14, 119, 176, 147, 148, 252,  93,  18, 249, 191, 110,
            223, 239,  43,  14, 150, 222,  74, 118,   2
          ].to_vec();
        let mut contract = Contract::new(PublicKey::from_str("ed25519:6BTMQWnxGDrzWizymRMdnRsofDMRJ1assMUrym6kSEj9").unwrap());
        println!("go ..{:?}", contract.register_social("lens".to_string(), sig.clone(), "genadop.lens".to_string(), "0x11e231e6fbd69343389ba9b6179b0108b914ad3e687172ba5d7748212058477d63e4aa09114e9a9b23b3cae4da7300577809b650bdf8842e0d1fae6cb8144f1c1c".to_string(), 10));
        // println!("go on osnu.. {:?}", contract.get_user_connected_platforms(receiver.clone()));
        testing_env!(context
            .storage_usage(env::storage_usage())
            .attached_deposit(MINT_STORAGE_COST)
            .predecessor_account_id(receiver.clone())
            .signer_account_id(receiver.clone())
            .block_timestamp(7876000000002000)
            .build());
        println!("go ..{:?}", contract.register_social("lens".to_string(), sig.clone(), "genadop.lens".to_string(), "0x11e231e6fbd69343389ba9b6179b0108b914ad3e687172ba5d7748212058477d63e4aa09114e9a9b23b3cae4da7300577809b650bdf8842e0d1fae6cb8144f1c1c".to_string(), 10));
        // println!("after round 1.. {}", contract.six_month_old(receiver));
    }


}
#![no_std]

use soroban_sdk::{contractimpl, contracttype, Address, BytesN, Env, Symbol};

/// NFT metadata (could be extended with more fields)
#[derive(Clone)]
#[contracttype]
pub struct NftMetadata {
    pub name: Symbol,
    pub description: Symbol,
    pub image_url: Symbol,
    pub is_active: bool, // Used for revocation
}

/// The contract storage keys
#[contracttype]
enum DataKey {
    Admin,
    NftOwner(BytesN<32>), // NFT ID -> Owner Address
    OwnerNft(Address),    // Owner Address -> NFT ID
    NftMetadata(BytesN<32>), // NFT ID -> Metadata
}

pub struct AccessNftContract;

#[contractimpl]
impl AccessNftContract {
    /// Initialize the contract, setting the admin/issuer
    pub fn initialize(env: Env, admin: Address) {
        assert!(!env.storage().has(&DataKey::Admin), "Already initialized");
        env.storage().set(&DataKey::Admin, &admin);
    }

    /// Mint a new NFT for a user (only admin can mint)
    pub fn mint_nft(
        env: Env,
        to: Address,
        name: Symbol,
        description: Symbol,
        image_url: Symbol,
    ) -> BytesN<32> {
        let admin: Address = env.storage().get_unchecked(&DataKey::Admin).unwrap();
        admin.require_auth();

        // Only one NFT per user (for simplicity)
        if env.storage().has(&DataKey::OwnerNft(to.clone())) {
            panic!("User already owns an NFT");
        }

        // Generate NFT ID (hash of (to, name, timestamp))
        let id = env.crypto().sha256(&(to.serialize(&env), name.to_bytes(&env), env.ledger().timestamp().to_be_bytes().into()).concat());

        // Store ownership and metadata
        env.storage().set(&DataKey::NftOwner(id.clone()), &to);
        env.storage().set(&DataKey::OwnerNft(to.clone()), &id);
        let meta = NftMetadata {
            name,
            description,
            image_url,
            is_active: true,
        };
        env.storage().set(&DataKey::NftMetadata(id.clone()), &meta);

        id
    }

    /// Check if a user has an active NFT (for access control)
    pub fn has_access(env: Env, user: Address) -> bool {
        if let Some(id) = env.storage().get(&DataKey::OwnerNft(user.clone())) {
            let meta: NftMetadata = env.storage().get_unchecked(&DataKey::NftMetadata(id)).unwrap();
            meta.is_active
        } else {
            false
        }
    }

    /// Get NFT metadata for a user
    pub fn get_nft_metadata(env: Env, user: Address) -> Option<NftMetadata> {
        if let Some(id) = env.storage().get(&DataKey::OwnerNft(user.clone())) {
            env.storage().get(&DataKey::NftMetadata(id))
        } else {
            None
        }
    }

    /// Admin can revoke (deactivate) a user's NFT
    pub fn revoke_nft(env: Env, user: Address) {
        let admin: Address = env.storage().get_unchecked(&DataKey::Admin).unwrap();
        admin.require_auth();

        if let Some(id) = env.storage().get(&DataKey::OwnerNft(user.clone())) {
            let mut meta: NftMetadata = env.storage().get_unchecked(&DataKey::NftMetadata(id.clone())).unwrap();
            meta.is_active = false;
            env.storage().set(&DataKey::NftMetadata(id), &meta);
        } else {
            panic!("User does not own an NFT");
        }
    }

    /// Admin can re-activate a user's NFT
    pub fn reactivate_nft(env: Env, user: Address) {
        let admin: Address = env.storage().get_unchecked(&DataKey::Admin).unwrap();
        admin.require_auth();

        if let Some(id) = env.storage().get(&DataKey::OwnerNft(user.clone())) {
            let mut meta: NftMetadata = env.storage().get_unchecked(&DataKey::NftMetadata(id.clone())).unwrap();
            meta.is_active = true;
            env.storage().set(&DataKey::NftMetadata(id), &meta);
        } else {
            panic!("User does not own an NFT");
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::testutils::{Address as _, Ledger};

    fn setup() -> (Env, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::random(&env);
        let user = Address::random(&env);
        AccessNftContract::initialize(env.clone(), admin.clone());
        (env, admin, user)
    }

    #[test]
    fn test_mint_and_access() {
        let (env, _admin, user) = setup();
        env.ledger().with_mut(|l| l.timestamp = 1);
        let id = AccessNftContract::mint_nft(
            env.clone(),
            user.clone(),
            Symbol::short("Name"),
            Symbol::short("Desc"),
            Symbol::short("Img"),
        );
        assert!(env.storage().has(&DataKey::NftOwner(id.clone())));
        assert!(AccessNftContract::has_access(env.clone(), user.clone()));
        let meta = AccessNftContract::get_nft_metadata(env.clone(), user.clone()).unwrap();
        assert!(meta.is_active);
    }

    #[test]
    fn test_revoke_and_reactivate() {
        let (env, _admin, user) = setup();
        env.ledger().with_mut(|l| l.timestamp = 2);
        let _ = AccessNftContract::mint_nft(
            env.clone(),
            user.clone(),
            Symbol::short("Name"),
            Symbol::short("Desc"),
            Symbol::short("Img"),
        );
        AccessNftContract::revoke_nft(env.clone(), user.clone());
        assert!(!AccessNftContract::has_access(env.clone(), user.clone()));
        AccessNftContract::reactivate_nft(env.clone(), user.clone());
        assert!(AccessNftContract::has_access(env.clone(), user.clone()));
    }
}

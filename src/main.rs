use candid::{CandidType, Decode, Deserialize, Encode, Principal};
use ic_cdk::management_canister::canister_status;
use ic_management_canister_types::CanisterIdRecord;
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
#[cfg(not(target_arch = "wasm32"))]
use ic_stable_structures::{file_mem::FileMemory, StableBTreeMap};
use ic_stable_structures::{storable::Bound, Storable};
#[cfg(target_arch = "wasm32")]
use ic_stable_structures::{DefaultMemoryImpl, StableBTreeMap};
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::HashSet;
use std::fmt::Debug;
#[macro_use]
extern crate num_derive;

#[cfg(not(target_arch = "wasm32"))]
type Memory = VirtualMemory<FileMemory>;
#[cfg(target_arch = "wasm32")]
type Memory = VirtualMemory<DefaultMemoryImpl>;

type Blob = Vec<u8>;

const WASM_PAGE_SIZE: u64 = 65536;

#[derive(Clone, Debug, Default, CandidType, Deserialize)]
struct Profile {
    updated_time_msecs: Option<u64>,
    username: Option<String>,
    password: Option<String>,
    email: Option<String>,
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug, CandidType, Deserialize)]
struct PrincipalStorable(Principal);

#[derive(Clone, Debug, CandidType, Deserialize, FromPrimitive)]
enum Auth {
    Admin,
}

impl Storable for Profile {
    fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        Decode!(&bytes, Self).unwrap()
    }

    const BOUND: Bound = Bound::Bounded {
        max_size: 256,
        is_fixed_size: false,
    };
}

impl Storable for PrincipalStorable {
    fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
        Cow::Owned(self.0.as_slice().to_vec())
    }

    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        PrincipalStorable(Principal::from_slice(&bytes))
    }

    const BOUND: Bound = Bound::Bounded {
        max_size: 29,
        is_fixed_size: false,
    };
}

thread_local! {
#[cfg(not(target_arch = "wasm32"))]
    static MEMORY_MANAGER: RefCell<MemoryManager<FileMemory>> =
        RefCell::new(MemoryManager::init(FileMemory::new(std::fs::OpenOptions::new().read(true).write(true).create(true).open("backup/stable_memory.dat").unwrap())));
#[cfg(target_arch = "wasm32")]
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));
    static PROFILES: RefCell<StableBTreeMap<PrincipalStorable, Profile, Memory>> = RefCell::new(
        StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0))))
    );
    static AUTH: RefCell<StableBTreeMap<PrincipalStorable, u32, Memory>> = RefCell::new(
        StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(3))))
    );
    static AUTH_STABLE: RefCell<HashSet<Principal>> = RefCell::new(HashSet::<Principal>::new());
}

#[ic_cdk_macros::update]
#[candid::candid_method(update)]
async fn set_profile(profile: Profile) -> Profile {
    let user = PrincipalStorable(ic_cdk::api::msg_caller());
    let old_profile = PROFILES.with(|p| {
        if let Some(old_profile) = p.borrow().get(&user) {
            if old_profile.updated_time_msecs >= profile.updated_time_msecs {
                return Some(old_profile);
            }
        }
        None
    });
    if let Some(old_profile) = old_profile {
        return old_profile;
    }
    let mut profile = profile;
    if profile.password == None {
        let raw_rand: Vec<u8> = ic_cdk::management_canister::raw_rand()
            .await
            .unwrap_or_else(|err| ic_cdk::trap(&format!("failed to get rand: {}", err)));
        profile.password = Some(hex::encode(Sha256::digest(raw_rand)));
    }
    PROFILES.with(|p| {
        p.borrow_mut().insert(user, profile.clone()).unwrap();
        profile
    })
}

#[ic_cdk_macros::update]
#[candid::candid_method(update)]
async fn register(profile: Profile) -> Profile {
    let user = PrincipalStorable(ic_cdk::api::msg_caller());
    let user_text = ic_cdk::api::msg_caller().to_text();
    let mut profile = profile;
    PROFILES.with(|p| {
        if !p.borrow().contains_key(&user) {
            if profile.updated_time_msecs == None {
                profile.updated_time_msecs = Some(ic_cdk::api::time() / 1000000);
            }
            if profile.username == None {
                profile.username = Some(user_text.clone());
            }
        } else {
            ic_cdk::api::trap(&"User already registered.");
        }
    });
    if profile.password == None {
        let raw_rand: Vec<u8> = ic_cdk::management_canister::raw_rand()
            .await
            .unwrap_or_else(|err| ic_cdk::trap(&format!("failed to get rand: {}", err)));
        profile.password = Some(hex::encode(Sha256::digest(raw_rand)));
    }
    PROFILES.with(|p| {
        p.borrow_mut().insert(user, profile.clone()).unwrap();
        profile
    })
}

#[ic_cdk_macros::query]
#[candid::candid_method(query)]
fn login() -> Profile {
    let user = PrincipalStorable(ic_cdk::api::msg_caller());
    PROFILES.with(|p| {
        if !p.borrow().contains_key(&user) {
            ic_cdk::api::trap(&"User not found.");
        }
        p.borrow().get(&user).unwrap()
    })
}

#[ic_cdk_macros::query(guard = "is_authorized")]
#[candid::candid_method(query)]
fn backup(offset: u32, count: u32) -> Vec<(String, Profile)> {
    PROFILES.with(|p| {
        p.borrow()
            .iter()
            .skip(offset as usize)
            .take(count as usize)
            .map(|(k, p)| (k.0.to_text(), p))
            .collect()
    })
}

#[ic_cdk_macros::update(guard = "is_authorized")]
#[candid::candid_method(update)]
fn restore(profiles: Vec<(String, Profile)>) {
    PROFILES.with(|m| {
        let mut m = m.borrow_mut();
        for p in profiles {
            let principal = PrincipalStorable(Principal::from_text(p.0).unwrap());
            m.insert(principal, p.1).unwrap();
        }
    });
}

#[ic_cdk_macros::query(guard = "is_stable_authorized")]
#[candid::candid_method(query)]
fn stable_size() -> u64 {
    ic_cdk::stable::stable_size() * WASM_PAGE_SIZE
}

#[ic_cdk_macros::query(guard = "is_stable_authorized")]
#[candid::candid_method(query)]
fn stable_read(offset: u64, length: u64) -> Vec<u8> {
    let mut buffer = Vec::new();
    buffer.resize(length as usize, 0);
    ic_cdk::stable::stable_read(offset, buffer.as_mut_slice());
    buffer
}

#[ic_cdk_macros::update(guard = "is_stable_authorized")]
#[candid::candid_method(update)]
fn stable_write(offset: u64, buffer: Vec<u8>) {
    let size = offset + buffer.len() as u64;
    let old_size = ic_cdk::stable::stable_size() * WASM_PAGE_SIZE;
    if size > old_size {
        let old_pages = old_size / WASM_PAGE_SIZE;
        let pages = (size + (WASM_PAGE_SIZE - 1)) / WASM_PAGE_SIZE;
        ic_cdk::stable::stable_grow(pages - old_pages).unwrap();
    }
    ic_cdk::stable::stable_write(offset, buffer.as_slice());
}

#[ic_cdk_macros::query]
#[candid::candid_method(query)]
fn get_authorized() -> Vec<Principal> {
    let mut authorized = Vec::new();
    AUTH.with(|a| {
        for (k, _v) in a.borrow().iter() {
            authorized.push(k.0);
        }
    });
    authorized
}

#[ic_cdk_macros::update(guard = "is_authorized")]
#[candid::candid_method(update)]
fn authorize(principal: Principal) {
    authorize_principal(&principal);
}

#[ic_cdk_macros::update(guard = "is_stable_authorized")]
#[candid::candid_method(update)]
fn stable_authorize(principal: Principal) {
    AUTH_STABLE.with(|a| a.borrow_mut().insert(principal));
}

#[ic_cdk_macros::update(guard = "is_authorized")]
#[candid::candid_method(update)]
fn deauthorize(principal: Principal) {
    AUTH.with(|a| {
        a.borrow_mut()
            .remove(&PrincipalStorable(principal))
            .unwrap();
    });
}

#[ic_cdk_macros::init]
fn canister_init() {
    authorize_principal(&ic_cdk::api::msg_caller());
    stable_authorize(ic_cdk::api::msg_caller());
}

#[ic_cdk_macros::update(guard = "is_authorized")]
#[candid::candid_method(update)]
async fn authorize_controllers() {
    let status = canister_status(&CanisterIdRecord {
        canister_id: ic_cdk::api::canister_self(),
    })
    .await
    .unwrap();
    AUTH_STABLE.with(|a| {
        for p in status.settings.controllers.clone() {
            authorize_principal(&p);
            a.borrow_mut().insert(p);
        }
    });
}

fn is_authorized() -> Result<(), String> {
    AUTH.with(|a| {
        if a.borrow()
            .contains_key(&PrincipalStorable(ic_cdk::api::msg_caller()))
        {
            Ok(())
        } else {
            Err("You are not authorized".to_string())
        }
    })
}

fn is_stable_authorized() -> Result<(), String> {
    AUTH_STABLE.with(|a| {
        if a.borrow().contains(&ic_cdk::api::msg_caller()) {
            Ok(())
        } else {
            Err("You are not stable authorized".to_string())
        }
    })
}

fn authorize_principal(principal: &Principal) {
    let value = Auth::Admin;
    AUTH.with(|a| {
        a.borrow_mut()
            .insert(PrincipalStorable(*principal), value as u32)
            .unwrap();
    });
}

pub type HeaderField = (String, String);

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<HeaderField>,
    pub body: Blob,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct HttpResponse {
    pub status_code: u16,
    pub headers: Vec<HeaderField>,
    pub body: Blob,
}

#[ic_cdk_macros::query]
async fn http_request(_: HttpRequest) -> HttpResponse {
    let body = info();
    return HttpResponse {
        status_code: 200,
        headers: vec![
            ("Content-Type".to_string(), "text/plain".to_string()),
            ("Content-Length".to_string(), body.len().to_string()),
        ],
        body: body.into(),
    };
}

candid::export_service!();

fn info() -> String {
    "".to_string()
        + &format!("GIT_REPO=https://github.com/jplevyak/ic-icpone.git\n")
        + &format!("GIT_BRANCH={}\n", env!("VERGEN_GIT_BRANCH"))
        + &format!("GIT_SHA={}\n", env!("VERGEN_GIT_SHA"))
        + &format!(
            "GIT_COMMIT_TIMESTAMP={}\n",
            env!("VERGEN_GIT_COMMIT_TIMESTAMP")
        )
        + &format!("RUSTC_SEMVER={}\n", env!("VERGEN_RUSTC_SEMVER"))
        + &format!("BUILD_TIMESTAMP={}\n", env!("VERGEN_BUILD_TIMESTAMP"))
        + &format!("CANDID:\n{}\n", __export_service())
}

#[ic_cdk_macros::query(name = "__get_candid_interface_tmp_hack")]
fn export_candid() -> String {
    __export_service()
}

#[cfg(not(target_arch = "wasm32"))]
fn main() {
    println!("{}", export_candid());
    let principals = get_authorized();
    println!("authorized principals: {}", principals.len());
    for p in principals {
        println!("  {}", p.to_text());
    }
}

#[cfg(target_arch = "wasm32")]
fn main() {}

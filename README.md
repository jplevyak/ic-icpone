# ICPOne backend

This canister smart contract contains the ICPOne user data backend.

## Usage

User profiles contain:

```
type Profile = record {
  updated_time_msecs: opt nat64;
  username: opt text;
  password: opt text;
  email: opt text;
};
```

The contract presents the API:

```
service icpone: {
  register:  (Profile) -> (Profile);
  login:  () -> (Profile) query;
  set_profile: (Profile) -> (Profile);
  //
  // Backup/restore map from principal (in text) to Profile(s).
  //
  backup: () -> (vec record { text; Profile }) query;
  restore: (vec record { text; Profile }) -> ();
  // Raw backup/restore interface.
  stable_size : () -> (nat64);
  stable_read : (nat64, nat64) -> (vec nat8);
  stable_write : (nat64, vec nat8) -> ();
  //
  // Manage the set of Principals allowed to backup/restore.
  //
  authorize: (principal) -> ();
  deauthorize: (principal) -> ();
  get_authorized: () -> (vec principal) query;
}
```

## Backup and Restore

The canister uses stable memory to store all data, so it is not necessary to backup and restore the data under normal operation.  Nevertheless, the data can be backed up and restored e.g. to support arbitrary schema changes. The principal doing the backup and restore must first be authorized by the principal which installed the canister smart contract.  Sample code to backup and restore the data is the `./backup` directory.

The installation principal is assumed to be available as the default in `dfx`.  The backup and restore identity is assumed to be `icpone`.  The canister id of the canister smart contract is hard coded in the scripts.  These can be changed in the code.

A raw backup/restore interface is also available for debugging and last resort disaster recovery. The user is responsible for ensuring that there are no updates to the canister state during raw access to stable memory by (for example) `deauthorize`-ing everyone or installing a canister with only the `stable_xxx` methods.

### Backup

```
node backup.js > backup.dat
```

### Restore

```
node restore.js
```

## Development

### Depenedencies

* node, npm
* rustup, cargo, rustc with wasm

### Setup

* (cd backup; npm i)

### Build

* make build

### Test

* dfx start --background
* dfx deploy
* make test

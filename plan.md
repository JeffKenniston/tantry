1. **Fix `crates/iam/src/dpop.rs`**:
   - Change `SigningKey::from_pkcs8_der(svid.ed25519_seed.as_ref())` to use `from_bytes` or appropriately extract the seed.

2. **Fix `crates/iam/src/spire.rs`**:
   - Ensure the timestamps for target and now use the same units (milliseconds). `chrono::Utc::now().timestamp_millis()` should be used instead of `timestamp()`.

3. **Cleanup**:
   - Remove scratch files: `patch_svid.rs`, `patch_svid2.rs`, `patch_lib.rs`, `patch_lib`.

4. **Verify**:
   - Run tests and make sure the code compiles.

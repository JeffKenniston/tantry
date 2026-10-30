use core::fmt;
use std::any::{Any, TypeId};
use std::collections::{BTreeMap, HashMap};
use std::hash::{BuildHasherDefault, Hasher};
use std::sync::Arc;

use crate::error::ExtensionError;

/// TypeIdHasher: Identity `write_u64(&mut self, id: u64)` (`self.0 = id`) and FNV-1a `write(&mut self, bytes: &[u8])`.
#[derive(Default)]
pub struct TypeIdHasher(u64);

impl Hasher for TypeIdHasher {
    fn write(&mut self, bytes: &[u8]) {
        let mut hash = 14695981039346656037u64;
        for byte in bytes {
            hash ^= *byte as u64;
            hash = hash.wrapping_mul(1099511628211u64);
        }
        self.0 = hash;
    }

    fn write_u64(&mut self, id: u64) {
        self.0 = id;
    }

    fn finish(&self) -> u64 {
        self.0
    }
}

/// FastTypeMap type
pub type FastTypeMap<V> = HashMap<TypeId, V, BuildHasherDefault<TypeIdHasher>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// SlotVisibility enum
pub enum SlotVisibility {
    Private,
    Shared,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
/// CodecTag enum
pub enum CodecTag {
    RkyvAligned = 0x01,
    MessagePackNamed = 0x02,
}

/// StateSlot trait
pub trait StateSlot: Any + Send + Sync + Clone + 'static {
    const WIRE_KEY: &'static str;
    const VISIBILITY: SlotVisibility;
    const CODEC_TAG: CodecTag;

    fn encode_payload(&self) -> Result<Vec<u8>, ExtensionError>;
    fn decode_payload(bytes: &[u8]) -> Result<Self, ExtensionError>
    where
        Self: Sized;
}

/// ErasedSlot trait
pub trait ErasedSlot: Any + Send + Sync {
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;
    fn wire_key(&self) -> &'static str;
    fn visibility(&self) -> SlotVisibility;
    fn codec_tag(&self) -> CodecTag;
    fn encode_payload(&self) -> Result<Vec<u8>, ExtensionError>;
    fn clone_box(&self) -> Box<dyn ErasedSlot>;
    fn clone_shared_only(&self) -> Option<Box<dyn ErasedSlot>>;
}

#[derive(Clone)]
/// SlotHolder struct
pub struct SlotHolder<T: StateSlot>(Arc<T>);

impl<T: StateSlot> ErasedSlot for SlotHolder<T> {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
    fn wire_key(&self) -> &'static str {
        T::WIRE_KEY
    }
    fn visibility(&self) -> SlotVisibility {
        T::VISIBILITY
    }
    fn codec_tag(&self) -> CodecTag {
        T::CODEC_TAG
    }
    fn encode_payload(&self) -> Result<Vec<u8>, ExtensionError> {
        self.0.encode_payload()
    }
    fn clone_box(&self) -> Box<dyn ErasedSlot> {
        Box::new(self.clone())
    }
    fn clone_shared_only(&self) -> Option<Box<dyn ErasedSlot>> {
        if T::VISIBILITY == SlotVisibility::Shared {
            Some(self.clone_box())
        } else {
            None
        }
    }
}

/// StateExtensionRegistry trait
pub trait StateExtensionRegistry {
    fn decode_and_insert(
        &self,
        wire_key: &str,
        codec_tag: u8,
        payload: &[u8],
        map: &mut StateExtensionMap,
    ) -> Result<(), ExtensionError>;
}

// Default registry since it's referenced in specs.
/// DefaultExtensionRegistry struct
pub struct DefaultExtensionRegistry;

impl StateExtensionRegistry for DefaultExtensionRegistry {
    fn decode_and_insert(
        &self,
        wire_key: &str,
        _codec_tag: u8,
        _payload: &[u8],
        _map: &mut StateExtensionMap,
    ) -> Result<(), ExtensionError> {
        Err(ExtensionError::UnknownWireKey(wire_key.to_string()))
    }
}

#[derive(Default)]
/// StateExtensionMap struct
pub struct StateExtensionMap {
    inner: FastTypeMap<Box<dyn ErasedSlot>>,
}

impl Clone for StateExtensionMap {
    fn clone(&self) -> Self {
        let mut inner = FastTypeMap::default();
        for (k, v) in &self.inner {
            inner.insert(*k, v.clone_box());
        }
        Self { inner }
    }
}

impl fmt::Debug for StateExtensionMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StateExtensionMap")
            .field("slots", &self.inner.len())
            .finish()
    }
}

impl PartialEq for StateExtensionMap {
    fn eq(&self, other: &Self) -> bool {
        if self.inner.len() != other.inner.len() {
            return false;
        }
        // Serialization check since types are erased
        let left = self.serialize_all().unwrap_or_default();
        let right = other.serialize_all().unwrap_or_default();
        left == right
    }
}

impl StateExtensionMap {
    /// new fn
    pub fn new() -> Self {
        Self::default()
    }

    /// get fn
    pub fn get<T: StateSlot>(&self) -> Option<&T> {
        self.inner
            .get(&TypeId::of::<T>())
            .and_then(|b| b.as_any().downcast_ref::<SlotHolder<T>>())
            .map(|h| &*h.0)
    }

    /// get_mut fn
    pub fn get_mut<T: StateSlot>(&mut self) -> Option<&mut T> {
        if let Some(b) = self.inner.get_mut(&TypeId::of::<T>()) {
            #[allow(clippy::collapsible_if)]
            if let Some(h) = b.as_any_mut().downcast_mut::<SlotHolder<T>>() {
                return Some(Arc::make_mut(&mut h.0));
            }
        }
        None
    }

    /// insert fn
    pub fn insert<T: StateSlot>(&mut self, val: T) {
        self.inner
            .insert(TypeId::of::<T>(), Box::new(SlotHolder(Arc::new(val))));
    }

    /// remove fn
    pub fn remove<T: StateSlot>(&mut self) {
        self.inner.remove(&TypeId::of::<T>());
    }

    /// fork_shared_only fn
    pub fn fork_shared_only(&self) -> Self {
        let mut inner = FastTypeMap::default();
        for (k, v) in &self.inner {
            if v.visibility() == SlotVisibility::Shared {
                if let Some(shared) = v.clone_shared_only() {
                    inner.insert(*k, shared);
                }
            }
        }
        Self { inner }
    }

    /// serialize_all fn
    pub fn serialize_all(&self) -> Result<BTreeMap<String, Vec<u8>>, ExtensionError> {
        let mut result = BTreeMap::new();
        for v in self.inner.values() {
            let mut payload = vec![v.codec_tag() as u8];
            payload.extend(v.encode_payload()?);
            result.insert(v.wire_key().to_string(), payload);
        }
        Ok(result)
    }

    /// hydrate_all fn
    pub fn hydrate_all(
        &mut self,
        raw: &BTreeMap<String, Vec<u8>>,
        registry: &dyn StateExtensionRegistry,
    ) -> Result<(), ExtensionError> {
        for (wire_key, data) in raw {
            if data.is_empty() {
                return Err(ExtensionError::DeserializationFailed(
                    "Empty payload".to_string(),
                ));
            }
            let codec_tag = data[0];
            let payload = &data[1..];
            registry.decode_and_insert(wire_key, codec_tag, payload, self)?;
        }
        Ok(())
    }
}

#[derive(Default)]
/// DefaultExtensionRegistryImpl struct
pub struct DefaultExtensionRegistryImpl {
    #[allow(clippy::type_complexity)]
    decoders: HashMap<
        String,
        (
            u8,
            Box<dyn Fn(&[u8]) -> Result<(TypeId, Box<dyn ErasedSlot>), ExtensionError>>,
        ),
    >,
}

impl DefaultExtensionRegistryImpl {
    /// new fn
    pub fn new() -> Self {
        Self {
            decoders: HashMap::new(),
        }
    }
}

impl StateExtensionRegistry for DefaultExtensionRegistryImpl {
    fn decode_and_insert(
        &self,
        wire_key: &str,
        codec_tag: u8,
        payload: &[u8],
        map: &mut StateExtensionMap,
    ) -> Result<(), ExtensionError> {
        if let Some((expected_tag, decoder)) = self.decoders.get(wire_key) {
            if codec_tag != *expected_tag {
                return Err(ExtensionError::CodecTagMismatch {
                    expected: *expected_tag,
                    actual: codec_tag,
                });
            }
            let (type_id, erased) = decoder(payload)?;
            map.inner.insert(type_id, erased);
            Ok(())
        } else {
            Err(ExtensionError::UnknownWireKey(wire_key.to_string()))
        }
    }
}

/// register_slot fn
pub fn register_slot<T: StateSlot>(registry: &mut DefaultExtensionRegistryImpl) {
    registry.decoders.insert(
        T::WIRE_KEY.to_string(),
        (
            T::CODEC_TAG as u8,
            Box::new(|bytes| {
                let val = T::decode_payload(bytes)?;
                Ok((TypeId::of::<T>(), Box::new(SlotHolder(Arc::new(val)))))
            }),
        ),
    );
}

use crate::error::ExtensionError;
use std::any::{Any, TypeId};
use std::collections::{BTreeMap, HashMap};
use std::hash::{BuildHasherDefault, Hasher};
use std::sync::Arc;

#[derive(Default)]
pub struct TypeIdHasher(u64);

impl Hasher for TypeIdHasher {
    fn write_u64(&mut self, id: u64) {
        self.0 = id;
    }

    fn write(&mut self, bytes: &[u8]) {
        let mut hash = 0xcbf29ce484222325;
        for &byte in bytes {
            hash ^= byte as u64;
            hash = hash.wrapping_mul(0x100000001b3);
        }
        self.0 = hash;
    }

    fn finish(&self) -> u64 {
        self.0
    }
}

pub type FastTypeMap<V> = HashMap<TypeId, V, BuildHasherDefault<TypeIdHasher>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotVisibility {
    Private,
    Shared,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CodecTag {
    RkyvAligned = 0x01,
    MessagePackNamed = 0x02,
}

pub trait StateSlot: Any + Send + Sync + Clone + 'static {
    const WIRE_KEY: &'static str;
    const VISIBILITY: SlotVisibility;
    const CODEC_TAG: CodecTag;

    fn encode_payload(&self) -> Result<Vec<u8>, ExtensionError>;
    fn decode_payload(bytes: &[u8]) -> Result<Self, ExtensionError>
    where
        Self: Sized;
}

pub trait ErasedSlot: Any + Send + Sync {
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;
    fn visibility(&self) -> SlotVisibility;
    fn codec_tag(&self) -> CodecTag;
    fn wire_key(&self) -> &'static str;
    fn encode_erased(&self) -> Result<Vec<u8>, ExtensionError>;
    fn clone_erased(&self) -> Box<dyn ErasedSlot>;
    fn type_id_erased(&self) -> TypeId;
}

struct SlotHolder<T>(Arc<T>);

impl<T: StateSlot> ErasedSlot for SlotHolder<T> {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn visibility(&self) -> SlotVisibility {
        T::VISIBILITY
    }

    fn codec_tag(&self) -> CodecTag {
        T::CODEC_TAG
    }

    fn wire_key(&self) -> &'static str {
        T::WIRE_KEY
    }

    fn encode_erased(&self) -> Result<Vec<u8>, ExtensionError> {
        self.0.encode_payload()
    }

    fn clone_erased(&self) -> Box<dyn ErasedSlot> {
        Box::new(SlotHolder(self.0.clone()))
    }

    fn type_id_erased(&self) -> TypeId {
        TypeId::of::<T>()
    }
}

pub type StateExtensionRegistry =
    HashMap<String, fn(&[u8]) -> Result<Box<dyn ErasedSlot>, ExtensionError>>;

pub fn register_slot<T: StateSlot>(registry: &mut StateExtensionRegistry) {
    registry.insert(T::WIRE_KEY.to_string(), |bytes| {
        let decoded = T::decode_payload(bytes)?;
        Ok(Box::new(SlotHolder(Arc::new(decoded))))
    });
}

#[derive(Default)]
pub struct StateExtensionMap {
    map: FastTypeMap<Box<dyn ErasedSlot>>,
}

impl Clone for StateExtensionMap {
    fn clone(&self) -> Self {
        let mut map = FastTypeMap::default();
        for (id, slot) in &self.map {
            map.insert(*id, slot.clone_erased());
        }
        Self { map }
    }
}

impl std::fmt::Debug for StateExtensionMap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StateExtensionMap").finish()
    }
}

impl PartialEq for StateExtensionMap {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl StateExtensionMap {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get<T: StateSlot>(&self) -> Option<&T> {
        self.map.get(&TypeId::of::<T>()).and_then(|erased| {
            erased
                .as_any()
                .downcast_ref::<SlotHolder<T>>()
                .map(|holder| &*holder.0)
        })
    }

    pub fn get_mut<T: StateSlot>(&mut self) -> Option<&mut T> {
        if let Some(erased) = self.map.get_mut(&TypeId::of::<T>())
            && let Some(holder) = erased.as_any_mut().downcast_mut::<SlotHolder<T>>() {
                return Some(Arc::make_mut(&mut holder.0));
            }
        None
    }

    pub fn insert<T: StateSlot>(&mut self, val: T) {
        self.map
            .insert(TypeId::of::<T>(), Box::new(SlotHolder(Arc::new(val))));
    }

    pub fn remove<T: StateSlot>(&mut self) {
        self.map.remove(&TypeId::of::<T>());
    }

    pub fn fork_shared_only(&self) -> Self {
        let mut child = FastTypeMap::default();
        for (id, slot) in &self.map {
            if slot.visibility() == SlotVisibility::Shared {
                child.insert(*id, slot.clone_erased());
            }
        }
        Self { map: child }
    }

    pub fn serialize_all(&self) -> Result<BTreeMap<String, Vec<u8>>, ExtensionError> {
        let mut result = BTreeMap::new();
        for slot in self.map.values() {
            let mut payload = vec![slot.codec_tag() as u8];
            let encoded = slot.encode_erased()?;
            payload.extend_from_slice(&encoded);
            result.insert(slot.wire_key().to_string(), payload);
        }
        Ok(result)
    }

    pub fn hydrate_all(
        &mut self,
        raw: &BTreeMap<String, Vec<u8>>,
        registry: &StateExtensionRegistry,
    ) -> Result<(), ExtensionError> {
        for (key, payload) in raw {
            if payload.is_empty() {
                return Err(ExtensionError::DeserializationFailed(
                    "Empty payload".into(),
                ));
            }

            let tag_byte = payload[0];
            let bytes = &payload[1..];

            if let Some(decoder) = registry.get(key) {
                let decoded = decoder(bytes)?;
                if decoded.codec_tag() as u8 != tag_byte {
                    return Err(ExtensionError::CodecTagMismatch {
                        expected: decoded.codec_tag() as u8,
                        actual: tag_byte,
                    });
                }
                self.map.insert(decoded.type_id_erased(), decoded);
            } else {
                return Err(ExtensionError::UnknownWireKey(key.clone()));
            }
        }
        Ok(())
    }
}

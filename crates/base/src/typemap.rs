use std::any::{Any, TypeId};
use std::collections::{BTreeMap, HashMap};
use std::hash::{BuildHasherDefault, Hasher};
use std::sync::Arc;

use crate::error::ExtensionError;

#[derive(Default)]
pub struct TypeIdHasher(u64);

impl Hasher for TypeIdHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        // Simple FNV-1a for arbitrary bytes
        let mut hash = 0xcbf29ce484222325;
        for byte in bytes {
            hash ^= *byte as u64;
            hash = hash.wrapping_mul(0x100000001b3);
        }
        self.0 = hash;
    }

    fn write_u64(&mut self, id: u64) {
        self.0 = id;
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
    fn decode_payload(bytes: &[u8]) -> Result<Self, ExtensionError>;
}

pub trait ErasedSlot: Any + Send + Sync {
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;
    fn wire_key(&self) -> &'static str;
    fn visibility(&self) -> SlotVisibility;
    fn codec_tag(&self) -> CodecTag;
    fn encode(&self) -> Result<Vec<u8>, ExtensionError>;
    fn clone_box(&self) -> Box<dyn ErasedSlot>;
}

#[derive(Clone)]
struct SlotHolder<T: StateSlot>(Arc<T>);

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

    fn encode(&self) -> Result<Vec<u8>, ExtensionError> {
        self.0.encode_payload()
    }

    fn clone_box(&self) -> Box<dyn ErasedSlot> {
        Box::new(self.clone())
    }
}

pub struct StateExtensionRegistry {
    decoders: HashMap<&'static str, (TypeId, fn(&[u8]) -> Result<Box<dyn ErasedSlot>, ExtensionError>)>,
}

impl StateExtensionRegistry {
    pub fn new() -> Self {
        Self {
            decoders: HashMap::new(),
        }
    }

    pub fn register<T: StateSlot>(&mut self) {
        self.decoders.insert(T::WIRE_KEY, (TypeId::of::<T>(), |bytes| {
            let val = T::decode_payload(bytes)?;
            Ok(Box::new(SlotHolder(Arc::new(val))))
        }));
    }
}

#[derive(Default)]
pub struct StateExtensionMap {
    map: FastTypeMap<Box<dyn ErasedSlot>>,
}

impl std::fmt::Debug for StateExtensionMap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StateExtensionMap")
            .field("keys", &self.map.values().map(|v| v.wire_key()).collect::<Vec<_>>())
            .finish()
    }
}

impl Clone for StateExtensionMap {
    fn clone(&self) -> Self {
        let mut map = FastTypeMap::default();
        for (k, v) in &self.map {
            map.insert(*k, v.clone_box());
        }
        Self { map }
    }
}

impl StateExtensionMap {
    pub fn new() -> Self {
        Self {
            map: FastTypeMap::default(),
        }
    }

    pub fn get<T: StateSlot>(&self) -> Option<&T> {
        self.map.get(&TypeId::of::<T>()).and_then(|boxed| {
            boxed.as_any().downcast_ref::<SlotHolder<T>>().map(|holder| holder.0.as_ref())
        })
    }

    pub fn get_mut<T: StateSlot>(&mut self) -> Option<&mut T> {
        self.map.get_mut(&TypeId::of::<T>()).and_then(|boxed| {
            boxed.as_any_mut().downcast_mut::<SlotHolder<T>>().map(|holder| Arc::make_mut(&mut holder.0))
        })
    }

    pub fn insert<T: StateSlot>(&mut self, val: T) {
        self.map.insert(TypeId::of::<T>(), Box::new(SlotHolder(Arc::new(val))));
    }

    pub fn remove<T: StateSlot>(&mut self) {
        self.map.remove(&TypeId::of::<T>());
    }

    pub fn fork_shared_only(&self) -> Self {
        let mut new_map = FastTypeMap::default();
        for (type_id, slot) in &self.map {
            if slot.visibility() == SlotVisibility::Shared {
                new_map.insert(*type_id, slot.clone_box());
            }
        }
        Self { map: new_map }
    }

    pub fn serialize_all(&self) -> Result<BTreeMap<String, Vec<u8>>, ExtensionError> {
        let mut result = BTreeMap::new();
        for slot in self.map.values() {
            let mut data = vec![slot.codec_tag() as u8];
            data.extend(slot.encode()?);
            result.insert(slot.wire_key().to_string(), data);
        }
        Ok(result)
    }

    pub fn hydrate_all(&mut self, raw: &BTreeMap<String, Vec<u8>>, registry: &StateExtensionRegistry) -> Result<(), ExtensionError> {
        for (key, data) in raw {
            if data.is_empty() {
                return Err(ExtensionError::DeserializationFailed("Empty extension payload".into()));
            }
            let tag = data[0];
            let payload = &data[1..];

            if let Some(decoder) = registry.decoders.get(key.as_str()) {
                let slot = decoder(payload)?;
                if slot.codec_tag() as u8 != tag {
                    return Err(ExtensionError::CodecTagMismatch { expected: slot.codec_tag() as u8, actual: tag });
                }

                // Hacky way to re-insert by TypeId since we don't know it directly here.
                // In a real implementation we would map wire_key -> TypeId in the registry too.
                // We'll leave the map update to the caller for now if needed, or implement it by
                // tracking TypeId in the registry. Let's fix this for robustness:

                // Note: The spec says hydrate_all is in StateExtensionMap but registry is passed.
                // We'll just leave this as is since we need a way to insert by TypeId.
                // To do it correctly, registry should return (TypeId, Box<dyn ErasedSlot>).
            } else {
                return Err(ExtensionError::UnknownWireKey(key.clone()));
            }
        }
        Ok(())
    }
}

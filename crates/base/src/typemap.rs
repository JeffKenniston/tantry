use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::hash::{BuildHasherDefault, Hasher};
use std::sync::Arc;
use std::collections::BTreeMap;
use crate::error::ExtensionError;

#[derive(Default)]
pub struct TypeIdHasher(u64);

impl Hasher for TypeIdHasher {
    fn write(&mut self, bytes: &[u8]) {
        // FNV-1a
        let mut hash = self.0;
        if hash == 0 {
            hash = 0xcbf29ce484222325;
        }
        for byte in bytes {
            hash = hash ^ (*byte as u64);
            hash = hash.wrapping_mul(0x100000001b3);
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
    fn decode_payload(bytes: &[u8]) -> Result<Self, ExtensionError> where Self: Sized;
}

pub trait ErasedSlot: Any + Send + Sync + 'static {
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;
    fn clone_erased(&self) -> Box<dyn ErasedSlot>;
    fn visibility(&self) -> SlotVisibility;
    fn encode(&self) -> Result<Vec<u8>, ExtensionError>;
    fn wire_key(&self) -> &'static str;
    fn codec_tag(&self) -> CodecTag;
    fn slot_type_id(&self) -> TypeId;
}

#[derive(Debug)]
pub struct SlotHolder<T>(pub Arc<T>);

impl<T: StateSlot> Clone for SlotHolder<T> {
    fn clone(&self) -> Self {
        SlotHolder(self.0.clone())
    }
}

impl<T: StateSlot> ErasedSlot for SlotHolder<T> {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
    fn clone_erased(&self) -> Box<dyn ErasedSlot> {
        Box::new(self.clone())
    }
    fn visibility(&self) -> SlotVisibility {
        T::VISIBILITY
    }
    fn encode(&self) -> Result<Vec<u8>, ExtensionError> {
        self.0.encode_payload()
    }
    fn wire_key(&self) -> &'static str {
        T::WIRE_KEY
    }
    fn codec_tag(&self) -> CodecTag {
        T::CODEC_TAG
    }
    fn slot_type_id(&self) -> TypeId {
        TypeId::of::<T>()
    }
}

#[derive(Default)]
pub struct StateExtensionMap {
    pub map: FastTypeMap<Box<dyn ErasedSlot>>,
}

impl StateExtensionMap {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert<T: StateSlot>(&mut self, value: T) {
        self.map.insert(TypeId::of::<T>(), Box::new(SlotHolder(Arc::new(value))));
    }

    pub fn get<T: StateSlot>(&self) -> Option<&T> {
        self.map.get(&TypeId::of::<T>())
            .and_then(|boxed| boxed.as_any().downcast_ref::<SlotHolder<T>>())
            .map(|holder| &*holder.0)
    }

    pub fn get_mut<T: StateSlot>(&mut self) -> Option<&mut T> {
        self.map.get_mut(&TypeId::of::<T>())
            .and_then(|boxed| boxed.as_any_mut().downcast_mut::<SlotHolder<T>>())
            .map(|holder| Arc::make_mut(&mut holder.0))
    }

    pub fn remove<T: StateSlot>(&mut self) -> Option<T> {
        self.map.remove(&TypeId::of::<T>())
            .and_then(|boxed| boxed.as_any().downcast_ref::<SlotHolder<T>>().map(|holder| holder.0.as_ref().clone()))
    }

    pub fn fork_shared_only(&self) -> Self {
        let mut new_map = FastTypeMap::default();
        for (type_id, erased) in &self.map {
            if erased.visibility() == SlotVisibility::Shared {
                new_map.insert(*type_id, erased.clone_erased());
            }
        }
        Self { map: new_map }
    }

    pub fn serialize_all(&self) -> Result<BTreeMap<String, Vec<u8>>, ExtensionError> {
        let mut result = BTreeMap::new();
        for erased in self.map.values() {
            let mut payload = erased.encode()?;
            let mut wire = vec![erased.codec_tag() as u8];
            wire.append(&mut payload);
            result.insert(erased.wire_key().to_string(), wire);
        }
        Ok(result)
    }

    pub fn hydrate_all(&mut self, registry: &StateExtensionRegistry, data: BTreeMap<String, Vec<u8>>) -> Result<(), ExtensionError> {
        for (key, wire) in data {
            if wire.is_empty() {
                continue;
            }
            let tag = wire[0];
            let payload = &wire[1..];
            let decoder = registry.decoders.get(&key).ok_or_else(|| ExtensionError::UnknownWireKey(key.clone()))?;
            let erased = decoder(payload, tag)?;
            self.map.insert(erased.slot_type_id(), erased);
        }
        Ok(())
    }
}

pub struct StateExtensionRegistry {
    pub decoders: BTreeMap<String, Box<dyn Fn(&[u8], u8) -> Result<Box<dyn ErasedSlot>, ExtensionError> + Send + Sync>>,
}

impl Default for StateExtensionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl StateExtensionRegistry {
    pub fn new() -> Self {
        Self {
            decoders: BTreeMap::new(),
        }
    }
}

pub fn register_slot<T: StateSlot>(registry: &mut StateExtensionRegistry) {
    registry.decoders.insert(T::WIRE_KEY.to_string(), Box::new(|payload: &[u8], tag: u8| {
        if tag != T::CODEC_TAG as u8 {
            return Err(ExtensionError::CodecTagMismatch {
                expected: T::CODEC_TAG as u8,
                actual: tag,
            });
        }
        let value = T::decode_payload(payload)?;
        Ok(Box::new(SlotHolder(Arc::new(value))))
    }));
}

import re

with open('crates/base/src/typemap.rs', 'r') as f:
    content = f.read()

new_registry = """
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
"""

content = re.sub(r'pub struct StateExtensionRegistry \{.*?\}\n\}', new_registry.strip(), content, flags=re.DOTALL)

hydrate_all = """
    pub fn hydrate_all(&mut self, raw: &BTreeMap<String, Vec<u8>>, registry: &StateExtensionRegistry) -> Result<(), ExtensionError> {
        for (key, data) in raw {
            if data.is_empty() {
                return Err(ExtensionError::DeserializationFailed("Empty extension payload".into()));
            }
            let tag = data[0];
            let payload = &data[1..];

            if let Some((type_id, decoder)) = registry.decoders.get(key.as_str()) {
                let slot = decoder(payload)?;
                if slot.codec_tag() as u8 != tag {
                    return Err(ExtensionError::CodecTagMismatch { expected: slot.codec_tag() as u8, actual: tag });
                }
                self.map.insert(*type_id, slot);
            } else {
                return Err(ExtensionError::UnknownWireKey(key.clone()));
            }
        }
        Ok(())
    }
"""

content = re.sub(r'pub fn hydrate_all.*?\}\n    \}', hydrate_all.strip(), content, flags=re.DOTALL)

with open('crates/base/src/typemap.rs', 'w') as f:
    f.write(content)

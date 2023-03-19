use std::fmt::Display;

use serde::{Deserialize, Serialize};

#[derive(PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub struct ProfileName<S> {
    pub given_name: S,
    pub family_name: Option<S>,
}

// Implements ProfileName::getJoinedName
impl<S: AsRef<str>> Display for ProfileName<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let given_name = self.given_name.as_ref();
        match (
            self.given_name.as_ref().is_empty(),
            self.family_name.as_ref().map(AsRef::as_ref),
        ) {
            (true, None) => Ok(()),
            (false, None) => write!(f, "{}", given_name),
            (true, Some(family_name)) => write!(f, "{}", family_name),
            (false, Some(family_name)) => {
                if self.is_cjkv() {
                    write!(f, "{} {}", family_name, given_name)
                } else {
                    write!(f, "{} {}", given_name, family_name)
                }
            },
        }
    }
}

impl<S: AsRef<str>> ProfileName<S> {
    pub fn as_ref(&self) -> ProfileName<&str> {
        ProfileName {
            given_name: self.given_name.as_ref(),
            family_name: self.family_name.as_ref().map(|x| x.as_ref()),
        }
    }

    pub fn is_cjkv(&self) -> bool {
        // XXX insert unicode magic here
        false
    }

    pub fn serialize(&self) -> Vec<u8> {
        if let Some(family_name) = self.family_name.as_ref() {
            self.given_name
                .as_ref()
                .as_bytes()
                .iter()
                .chain(std::iter::once(&0u8))
                .chain(family_name.as_ref().as_bytes())
                .copied()
                .collect()
        } else {
            self.given_name.as_ref().as_bytes().into()
        }
    }

    pub fn is_empty(&self) -> bool {
        self.given_name.as_ref() == "" && self.family_name.is_none()
    }
}

impl ProfileName<String> {
    /// Copying deserialization of a ProfileName.
    pub fn deserialize(
        data: &[u8],
    ) -> Result<Option<Self>, std::str::Utf8Error> {
        let parts: Vec<&[u8]> = data.split(|x| *x == 0).collect();
        match parts.len() {
            0 => Ok(None),
            1 => Ok(Some(Self {
                given_name: std::str::from_utf8(parts[0])?.to_string(),
                family_name: None,
            })),
            _ => Ok(Some(Self {
                given_name: std::str::from_utf8(parts[0])?.to_string(),
                family_name: Some(std::str::from_utf8(parts[1])?.to_string()),
            })),
        }
    }
}

impl<'de> ProfileName<&'de str> {
    pub fn empty() -> Self {
        ProfileName {
            given_name: "",
            family_name: None,
        }
    }

    /// Zero-copy deserialization of a ProfileName.
    pub fn deserialize<'inp: 'de>(
        data: &'inp [u8],
    ) -> Result<Option<Self>, std::str::Utf8Error> {
        let parts: Vec<&[u8]> = data.split(|x| *x == 0).collect();
        match parts.len() {
            0 => Ok(None),
            1 => Ok(Some(Self {
                given_name: std::str::from_utf8(parts[0])?,
                family_name: None,
            })),
            _ => Ok(Some(Self {
                given_name: std::str::from_utf8(parts[0])?,
                family_name: Some(std::str::from_utf8(parts[1])?),
            })),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_name() {
        let names = [
            ("foo", Some("bar")),
            ("foo", None),
            ("", None),
            ("", Some("bar")),
        ];

        for &(given_name, family_name) in &names {
            let uut_name = ProfileName::<&str> {
                given_name,
                family_name,
            };
            let ser = uut_name.serialize();
            let deserialized =
                ProfileName::<&str>::deserialize(&ser).expect("utf8");
            assert_eq!(Some(uut_name), deserialized);
        }
    }
}

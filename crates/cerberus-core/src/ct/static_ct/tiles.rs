use serde::{Deserialize, Serialize};

use crate::error::{CerberusError, Result};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StaticCtTileKind {
    Data,
    Tree { level: u8 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticCtTilePath {
    pub kind: StaticCtTileKind,
    pub index: u64,
    pub width: Option<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticCtTileMetadata {
    pub kind: String,
    pub level: Option<u8>,
    pub index: u64,
    pub width: Option<u8>,
    pub path: String,
    pub url: String,
    pub byte_len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticCtTile {
    pub path: StaticCtTilePath,
    pub url: String,
    pub bytes: Vec<u8>,
}

impl StaticCtTilePath {
    pub fn data(index: u64, width: Option<u8>) -> Result<Self> {
        let path = Self {
            kind: StaticCtTileKind::Data,
            index,
            width,
        };
        path.validate()?;
        Ok(path)
    }

    pub fn tree(level: u8, index: u64, width: Option<u8>) -> Result<Self> {
        let path = Self {
            kind: StaticCtTileKind::Tree { level },
            index,
            width,
        };
        path.validate()?;
        Ok(path)
    }

    pub fn path(&self) -> Result<String> {
        self.validate()?;

        let mut path = match &self.kind {
            StaticCtTileKind::Data => format!("tile/data/{}", encode_tile_index(self.index)),
            StaticCtTileKind::Tree { level } => {
                format!("tile/{}/{}", level, encode_tile_index(self.index))
            }
        };

        if let Some(width) = self.width {
            path.push_str(&format!(".p/{width}"));
        }

        Ok(path)
    }

    pub fn validate(&self) -> Result<()> {
        if let StaticCtTileKind::Tree { level } = &self.kind {
            if *level > 5 {
                return Err(CerberusError::CtSource(format!(
                    "Static CT tile level must be between 0 and 5: {level}"
                )));
            }
        }

        if let Some(width) = self.width {
            if width == 0 {
                return Err(CerberusError::CtSource(
                    "Static CT partial tile width must be between 1 and 255".to_string(),
                ));
            }
        }

        Ok(())
    }
}

impl StaticCtTile {
    pub fn metadata(&self) -> Result<StaticCtTileMetadata> {
        let (kind, level) = match &self.path.kind {
            StaticCtTileKind::Data => ("data".to_string(), None),
            StaticCtTileKind::Tree { level } => ("tree".to_string(), Some(*level)),
        };

        Ok(StaticCtTileMetadata {
            kind,
            level,
            index: self.path.index,
            width: self.path.width,
            path: self.path.path()?,
            url: self.url.clone(),
            byte_len: self.bytes.len(),
        })
    }
}

pub fn encode_tile_index(index: u64) -> String {
    let mut groups = Vec::new();
    let mut remaining = index;

    loop {
        groups.push(remaining % 1000);
        remaining /= 1000;
        if remaining == 0 {
            break;
        }
    }

    groups.reverse();

    groups
        .iter()
        .enumerate()
        .map(|(position, group)| {
            if position + 1 == groups.len() {
                format!("{group:03}")
            } else {
                format!("x{group:03}")
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

pub fn partial_tile_width(tree_size: u64, level: u8) -> Result<Option<u8>> {
    let count = level_entry_count(tree_size, level)?;
    let width = count % 256;

    if width == 0 {
        Ok(None)
    } else {
        Ok(Some(width as u8))
    }
}

pub fn latest_data_tile_for_size(tree_size: u64) -> Result<Option<StaticCtTilePath>> {
    latest_tile_for_size(tree_size, 0, true)
}

pub fn latest_tree_tile_for_size(tree_size: u64, level: u8) -> Result<Option<StaticCtTilePath>> {
    latest_tile_for_size(tree_size, level, false)
}

fn latest_tile_for_size(tree_size: u64, level: u8, data: bool) -> Result<Option<StaticCtTilePath>> {
    if tree_size == 0 {
        return Ok(None);
    }

    let count = level_entry_count(tree_size, level)?;

    if count == 0 {
        return Ok(None);
    }

    let width = (count % 256) as u8;
    let (index, partial_width) = if width == 0 {
        ((count / 256).saturating_sub(1), None)
    } else {
        (count / 256, Some(width))
    };

    if data {
        StaticCtTilePath::data(index, partial_width).map(Some)
    } else {
        StaticCtTilePath::tree(level, index, partial_width).map(Some)
    }
}

fn level_entry_count(tree_size: u64, level: u8) -> Result<u64> {
    if level > 5 {
        return Err(CerberusError::CtSource(format!(
            "Static CT tile level must be between 0 and 5: {level}"
        )));
    }

    let divisor = 256u64.pow(level as u32);
    Ok(tree_size / divisor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_small_tile_index() {
        assert_eq!(encode_tile_index(0), "000");
        assert_eq!(encode_tile_index(7), "007");
        assert_eq!(encode_tile_index(123), "123");
    }

    #[test]
    fn encodes_large_tile_index() {
        assert_eq!(encode_tile_index(1234), "x001/234");
        assert_eq!(encode_tile_index(1234067), "x001/x234/067");
    }

    #[test]
    fn builds_data_tile_path() {
        let path = StaticCtTilePath::data(1234067, None).unwrap();
        assert_eq!(path.path().unwrap(), "tile/data/x001/x234/067");
    }

    #[test]
    fn builds_partial_data_tile_path() {
        let path = StaticCtTilePath::data(273, Some(112)).unwrap();
        assert_eq!(path.path().unwrap(), "tile/data/273.p/112");
    }

    #[test]
    fn builds_tree_tile_path() {
        let path = StaticCtTilePath::tree(1, 4, None).unwrap();
        assert_eq!(path.path().unwrap(), "tile/1/004");
    }

    #[test]
    fn calculates_partial_width() {
        assert_eq!(partial_tile_width(70000, 0).unwrap(), Some(112));
        assert_eq!(partial_tile_width(70000, 1).unwrap(), Some(17));
        assert_eq!(partial_tile_width(70000, 2).unwrap(), Some(1));
    }

    #[test]
    fn calculates_latest_data_tile_for_partial_tree() {
        let path = latest_data_tile_for_size(70000).unwrap().unwrap();
        assert_eq!(path.index, 273);
        assert_eq!(path.width, Some(112));
        assert_eq!(path.path().unwrap(), "tile/data/273.p/112");
    }

    #[test]
    fn calculates_latest_data_tile_for_full_tree() {
        let path = latest_data_tile_for_size(512).unwrap().unwrap();
        assert_eq!(path.index, 1);
        assert_eq!(path.width, None);
        assert_eq!(path.path().unwrap(), "tile/data/001");
    }

    #[test]
    fn rejects_invalid_level() {
        assert!(StaticCtTilePath::tree(6, 0, None).is_err());
    }

    #[test]
    fn rejects_invalid_partial_width() {
        assert!(StaticCtTilePath::data(0, Some(0)).is_err());
    }
}

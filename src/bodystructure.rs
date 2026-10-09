use std::collections::HashMap;

use crate::rfc3501::body_structure::BodyStructure;

/// An utility parser helping to find the appropriate
/// section part from a FETCH response.
pub struct BodyStructParser<'a> {
    map: HashMap<Vec<u32>, &'a BodyStructure<'a>>,
}

impl<'a> BodyStructParser<'a> {
    /// Returns a new parser
    ///
    /// # Arguments
    ///
    /// * `root` - The root of the `BodyStructure response.
    pub fn new(root: &'a BodyStructure<'a>) -> Self {
        let mut parser = BodyStructParser {
            map: HashMap::new(),
        };

        parser.parse(Vec::new(), root);
        parser
    }

    /// Search particular element within the bodystructure.
    ///
    /// # Arguments
    ///
    /// * `func` - The filter used to search elements within the bodystructure.
    pub fn search(&self, func: impl Fn(&'a BodyStructure<'a>) -> bool) -> Option<Vec<u32>> {
        let elem: Vec<_> = self
            .map
            .iter()
            .filter_map(|(k, v)| {
                if func(v) {
                    let slice: &[u32] = k;
                    Some(slice)
                } else {
                    None
                }
            })
            .collect();
        elem.first().map(|a| a.to_vec())
    }

    /// Reetr
    fn parse(&mut self, path: Vec<u32>, node: &'a BodyStructure) {
        match node {
            BodyStructure::Multipart { bodies, .. } => {
                for (i, body) in bodies.iter().enumerate() {
                    let mut path = path.clone();
                    path.push(i as u32 + 1);
                    self.parse(path, body);
                }
            }
            BodyStructure::Basic { .. }
            | BodyStructure::Text { .. }
            | BodyStructure::Message { .. } => {}
        }
        self.map.insert(path, node);
    }
}

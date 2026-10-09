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
        let mut map = HashMap::new();
        let mut stack = vec![(Vec::new(), root)];
        while let Some((path, node)) = stack.pop() {
            match node {
                BodyStructure::Multipart { bodies, .. } => {
                    for (i, body) in bodies.iter().enumerate() {
                        let mut path = path.clone();
                        path.push(i as u32 + 1);
                        stack.push((path, body));
                    }
                }
                BodyStructure::Basic { .. }
                | BodyStructure::Text { .. }
                | BodyStructure::Message { .. } => {}
            }
            map.insert(path, node);
        }

        BodyStructParser { map }
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
}

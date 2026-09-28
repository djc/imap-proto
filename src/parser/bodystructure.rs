use std::collections::HashMap;

use crate::parser::rfc3501::body_structure::BodyStructure;
/// An utility parser helping to find the appropriate
/// section part from a FETCH response.
pub struct BodyStructParser<'a> {
    root: &'a BodyStructure<'a>,
    prefix: Vec<u32>,
    iter: u32,
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
            root,
            prefix: vec![],
            iter: 1,
            map: HashMap::new(),
        };

        parser.parse(parser.root);
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
    fn parse(&mut self, node: &'a BodyStructure) {
        match node {
            BodyStructure::Multipart { bodies, .. } => {
                let vec = self.prefix.clone();
                self.map.insert(vec, node);

                for (i, n) in bodies.iter().enumerate() {
                    self.iter += i as u32;
                    self.prefix.push(self.iter);
                    self.parse(n);
                    self.prefix.pop();
                }
                self.iter = 1;
            }
            _ => {
                let vec = self.prefix.clone();
                self.map.insert(vec, node);
            }
        };
    }
}

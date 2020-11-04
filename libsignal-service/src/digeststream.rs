use std::io::Read;

use sha2::{Digest, Sha256};

pub struct DigestingReader<'r, R> {
    inner: &'r mut R,
    digest: Sha256,
}

impl<'r, R: Read> Read for DigestingReader<'r, R> {
    fn read(&mut self, tgt: &mut [u8]) -> Result<usize, std::io::Error> {
        let amount = self.inner.read(tgt)?;
        self.digest.update(&tgt[..amount]);
        Ok(amount)
    }
}

impl<'r, R: Read> DigestingReader<'r, R> {
    pub fn new(inner: &'r mut R) -> Self {
        Self {
            inner,
            digest: Sha256::new(),
        }
    }

    pub fn finalize(self) -> Vec<u8> {
        // XXX representation is not ideal, but this leaks to the public interface and I don't
        // really like exposing the GenericArray.
        Vec::from(self.digest.finalize().as_slice())
    }
}

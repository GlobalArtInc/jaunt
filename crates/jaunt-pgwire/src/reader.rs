use crate::error::Problem;

pub(crate) struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    pub(crate) fn position(&self) -> usize {
        self.position
    }

    pub(crate) fn remaining(&self) -> usize {
        self.bytes.len() - self.position
    }

    pub(crate) fn take(&mut self, count: usize) -> Result<&'a [u8], Problem> {
        if self.remaining() < count {
            return Err(Problem::Truncated);
        }
        let start = self.position;
        self.position += count;
        Ok(&self.bytes[start..self.position])
    }

    pub(crate) fn rest(&mut self) -> &'a [u8] {
        let start = self.position;
        self.position = self.bytes.len();
        &self.bytes[start..]
    }

    pub(crate) fn u8(&mut self) -> Result<u8, Problem> {
        Ok(self.take(1)?[0])
    }

    pub(crate) fn i16(&mut self) -> Result<i16, Problem> {
        let bytes = self.take(2)?;
        Ok(i16::from_be_bytes([bytes[0], bytes[1]]))
    }

    pub(crate) fn i32(&mut self) -> Result<i32, Problem> {
        let bytes = self.take(4)?;
        Ok(i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub(crate) fn u32(&mut self) -> Result<u32, Problem> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub(crate) fn count(&mut self) -> Result<usize, Problem> {
        usize::try_from(self.i16()?).map_err(|_| Problem::NegativeCount)
    }

    pub(crate) fn cstr(&mut self) -> Result<&'a [u8], Problem> {
        let rest = &self.bytes[self.position..];
        let end = rest
            .iter()
            .position(|byte| *byte == 0)
            .ok_or(Problem::MissingTerminator)?;
        self.position += end + 1;
        Ok(&rest[..end])
    }

    pub(crate) fn finish(&self) -> Result<(), Problem> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(Problem::TrailingBytes)
        }
    }
}

pub(crate) fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

pub(crate) fn length_field(bytes: &[u8]) -> Option<usize> {
    let field: [u8; 4] = bytes.get(..4)?.try_into().ok()?;
    usize::try_from(i32::from_be_bytes(field)).ok()
}

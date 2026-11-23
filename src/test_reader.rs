//! A reader that plays back a fixed script of reads and failures, for tests
//! of what the iterators do when the source misbehaves.

use std::collections::VecDeque;
use std::io::{self, ErrorKind, Read};

/// One call to `read`: the bytes it hands back, or the error it fails with.
pub(crate) enum Step {
    Data(&'static [u8]),
    Fail(ErrorKind),
}

/// Plays back `script`, one step per `read`; once it runs out, every read
/// fails with `then`, or returns end of input when `then` is `None`.
pub(crate) struct ScriptedReader {
    script: VecDeque<Step>,
    then: Option<ErrorKind>,
}

impl ScriptedReader {
    pub(crate) fn new(script: Vec<Step>, then: Option<ErrorKind>) -> Self {
        ScriptedReader {
            script: script.into(),
            then,
        }
    }
}

impl Read for ScriptedReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.script.pop_front() {
            Some(Step::Data(data)) => {
                assert!(
                    data.len() <= buf.len(),
                    "a scripted read must fit the buffer"
                );
                buf[..data.len()].copy_from_slice(data);
                Ok(data.len())
            }
            Some(Step::Fail(kind)) => Err(kind.into()),
            None => match self.then {
                Some(kind) => Err(kind.into()),
                None => Ok(0),
            },
        }
    }
}

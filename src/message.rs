use crate::{KBKey, MSButton};
use strum::FromRepr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, FromRepr)]
#[repr(u8)]
pub enum MessageTy {
	ClientFeatures,
	ServerFeatures,
	MSPress,
	MSRelease,
	MSMotion,
	MSScrollV,
	MSScrollH,
	KBPress,
	KBRelease,
	AudioChunk,
}

#[derive(Clone, PartialEq)]
pub enum Message {
	ClientFeatures {
		audio: bool,
	},
	ServerFeatures {
		audio: Option<(u8, u16)>,
	},
	MSPress(MSButton),
	MSRelease(MSButton),
	MSMotion(i32, i32),
	MSScrollV(i16),
	MSScrollH(i16),
	KBPress(KBKey),
	KBRelease(KBKey),
	AudioChunk {
		channels: u8,
		sample_rate: u16,
		data: Vec<f32>,
	},
}

impl std::fmt::Debug for Message {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::ClientFeatures {
				audio,
			} => write!(f, "Message::ClientFeatures {{ audio: {} }}", audio),
			Self::ServerFeatures {
				audio,
			} =>
				match audio {
					Some((c, s)) => write!(f, "Message::ServerFeatures {{ audio: Some(({}, {})) }}", c, s),
					None => write!(f, "Message::ServerFeatures {{ audio: None }}"),
				},
			Self::MSPress(button) => write!(f, "Message::MSPress({:?})", button),
			Self::MSRelease(button) => write!(f, "Message::MSRelease({:?})", button),
			Self::MSMotion(x, y) => write!(f, "Message::MSMotion({}, {})", x, y),
			Self::MSScrollV(amt) => write!(f, "Message::MSScrollV({})", amt),
			Self::MSScrollH(amt) => write!(f, "Message::MSScrollH({})", amt),
			Self::KBPress(key) => write!(f, "Message::KBPress({:?})", key),
			Self::KBRelease(key) => write!(f, "Message::KBPress({:?})", key),
			Self::AudioChunk {
				channels,
				sample_rate,
				data,
			} =>
				write!(
					f,
					"Message::AudioChunk {{ channels {}, sample_rate: {}, data: [f32; {}] }}",
					channels,
					sample_rate,
					data.len()
				),
		}
	}
}

impl Message {
	pub fn ty(&self) -> MessageTy {
		match self {
			Self::ClientFeatures {
				..
			} => MessageTy::ClientFeatures,
			Self::ServerFeatures {
				..
			} => MessageTy::ServerFeatures,
			Self::MSPress(_) => MessageTy::MSPress,
			Self::MSRelease(_) => MessageTy::MSRelease,
			Self::MSMotion(..) => MessageTy::MSMotion,
			Self::MSScrollV(_) => MessageTy::MSScrollV,
			Self::MSScrollH(_) => MessageTy::MSScrollH,
			Self::KBPress(_) => MessageTy::KBPress,
			Self::KBRelease(_) => MessageTy::KBRelease,
			Self::AudioChunk {
				..
			} => MessageTy::AudioChunk,
		}
	}
}

impl Message {
	pub fn encode(self) -> Vec<u8> {
		let mut enc = Vec::new();
		enc.push(self.ty() as u8);

		match self {
			Self::ClientFeatures {
				audio,
			} => {
				enc.push(audio as u8);
			},
			Self::ServerFeatures {
				audio,
			} =>
				match audio {
					Some((c, sr)) => {
						enc.push(0);
						enc.push(c);
						enc.extend_from_slice(&sr.to_le_bytes());
					},
					None => {
						enc.push(0);
					},
				},
			Self::MSPress(button) | Self::MSRelease(button) => {
				enc.push(button as u8);
			},
			Self::MSMotion(x, y) => {
				enc.extend_from_slice(&x.to_le_bytes());
				enc.extend_from_slice(&y.to_le_bytes());
			},
			Self::MSScrollV(amt) | Self::MSScrollH(amt) => {
				enc.extend_from_slice(&amt.to_le_bytes());
			},
			Self::KBPress(key) | Self::KBRelease(key) => {
				enc.push(key as u8);
			},
			Self::AudioChunk {
				channels,
				sample_rate,
				data,
			} => {
				enc.push(channels);
				enc.extend_from_slice(&sample_rate.to_le_bytes());
				enc.extend_from_slice(&(data.len() as u16).to_le_bytes());
				enc.reserve(data.len() * 4);

				for sample in data {
					for byte in sample.to_le_bytes() {
						enc.push(byte);
					}
				}
			},
		}

		enc
	}

	pub fn decode(mut enc: Vec<u8>) -> Option<Self> {
		if enc.is_empty() {
			return None;
		}

		let ty = MessageTy::from_repr(enc[0])?;

		Some(match ty {
			MessageTy::ClientFeatures => {
				if enc.len() != 2 {
					return None;
				}

				let audio = match enc[1] {
					0 => false,
					1 => true,
					_ => return None,
				};

				Self::ClientFeatures {
					audio,
				}
			},
			MessageTy::ServerFeatures => {
				if enc.len() != 2 {
					return None;
				}

				if enc[1] == 0 {
					return Some(Self::ServerFeatures {
						audio: None,
					});
				}

				if enc.len() != 5 {
					return None;
				}

				let c = enc[2];
				let sr = u16::from_le_bytes(<[u8; 2]>::try_from(&enc[3..5]).unwrap());

				Self::ServerFeatures {
					audio: Some((c, sr)),
				}
			},
			ty @ MessageTy::MSPress | ty @ MessageTy::MSRelease => {
				if enc.len() != 2 {
					return None;
				}

				let button = MSButton::from_repr(enc[1])?;

				match ty {
					MessageTy::MSPress => Self::MSPress(button),
					MessageTy::MSRelease => Self::MSRelease(button),
					_ => unreachable!(),
				}
			},
			MessageTy::MSMotion => {
				if enc.len() != 9 {
					return None;
				}

				let x = i32::from_le_bytes(<[u8; 4]>::try_from(&enc[1..5]).unwrap());
				let y = i32::from_le_bytes(<[u8; 4]>::try_from(&enc[5..9]).unwrap());
				Self::MSMotion(x, y)
			},
			ty @ MessageTy::MSScrollV | ty @ MessageTy::MSScrollH => {
				if enc.len() != 3 {
					return None;
				}

				let amt = i16::from_le_bytes(<[u8; 2]>::try_from(&enc[1..3]).unwrap());

				match ty {
					MessageTy::MSScrollV => Self::MSScrollV(amt),
					MessageTy::MSScrollH => Self::MSScrollH(amt),
					_ => unreachable!(),
				}
			},
			ty @ MessageTy::KBPress | ty @ MessageTy::KBRelease => {
				if enc.len() != 2 {
					return None;
				}

				let key = KBKey::from_repr(enc[1])?;

				match ty {
					MessageTy::KBPress => Self::KBPress(key),
					MessageTy::KBRelease => Self::KBRelease(key),
					_ => unreachable!(),
				}
			},
			MessageTy::AudioChunk => {
				if enc.len() < 6 {
					return None;
				}

				let channels = enc[1];
				let sample_rate = u16::from_le_bytes(<[u8; 2]>::try_from(&enc[2..4]).unwrap());
				let data_len = u16::from_le_bytes(<[u8; 2]>::try_from(&enc[4..6]).unwrap()) as usize;

				if data_len == 0 || enc.len() - 6 != data_len * 4 {
					return None;
				}

				let mut data_bytes = enc.split_off(6).into_iter();
				let mut data = Vec::with_capacity(data_len);

				for _ in 0..data_len {
					data.push(f32::from_le_bytes([
						data_bytes.next().unwrap(),
						data_bytes.next().unwrap(),
						data_bytes.next().unwrap(),
						data_bytes.next().unwrap(),
					]));
				}

				Self::AudioChunk {
					channels,
					sample_rate,
					data,
				}
			},
		})
	}
}

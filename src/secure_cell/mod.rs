// Copyright 2018 (c) rust-themis developers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

pub use secure_cell::mode_context_imprint::SecureCellContextImprint;
pub use secure_cell::mode_seal::SecureCellSeal;
pub use secure_cell::mode_token_protect::SecureCellTokenProtect;

mod mode_context_imprint;
mod mode_seal;
mod mode_token_protect;

pub struct SecureCell<K, C> {
    master_key: K,
    user_context: Option<C>,
}

impl<K> SecureCell<K, K> {
    pub fn with_key(master_key: K) -> Self {
        SecureCell {
            master_key,
            user_context: None,
        }
    }
}

impl<K, C> SecureCell<K, C> {
    pub fn with_key_and_context(master_key: K, user_context: C) -> Self {
        Self {
            master_key,
            user_context: Some(user_context),
        }
    }
}

impl<K, C> SecureCell<K, C> {
    pub fn seal(self) -> SecureCellSeal<K, C> {
        SecureCellSeal(self)
    }

    pub fn token_protect(self) -> SecureCellTokenProtect<K, C> {
        SecureCellTokenProtect(self)
    }

    pub fn context_imprint(self) -> SecureCellContextImprint<K, C> {
        SecureCellContextImprint(self)
    }
}

impl<K, C> SecureCell<K, C>
    where
        K: AsRef<[u8]>,
        C: AsRef<[u8]>,
{
    fn master_key(&self) -> &[u8] {
        self.master_key.as_ref()
    }

    fn user_context(&self) -> &[u8] {
        self.user_context
            .as_ref()
            .map(|c| c.as_ref())
            .unwrap_or(&[])
    }
}

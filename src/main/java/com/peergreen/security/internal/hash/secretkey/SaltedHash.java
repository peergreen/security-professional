/*
 * Copyright 2013 Peergreen SAS
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.peergreen.security.internal.hash.secretkey;

import com.peergreen.security.hash.Hash;

/**
 * User: guillaume
 * Date: 21/03/13
 * Time: 10:10
 */
public class SaltedHash implements Hash {
    private byte[] hashedValue;
    private byte[] salt;
    private String encryption;

    public SaltedHash(byte[] hashedValue, byte[] salt) {
        this(hashedValue, salt, SecretKeyHashService.DEFAULT_ALGORITHM);
    }

    public SaltedHash(byte[] hashedValue, byte[] salt, String encryption) {
        this.hashedValue = hashedValue;
        this.salt = salt;
        this.encryption = encryption;
    }

    @Override public byte[] getHashedValue() {
        return hashedValue;
    }

    public byte[] getSalt() {
        return salt;
    }

    @Override public String getEncryption() {
        return encryption;
    }
}

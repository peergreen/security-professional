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

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.fail;

import java.util.Arrays;

import org.testng.annotations.Test;

import com.peergreen.security.hash.Hash;
import com.peergreen.security.internal.hash.secretkey.SecretKeyHashService;

/**
 * User: guillaume
 * Date: 21/03/13
 * Time: 12:34
 */
public class SecretKeyHashServiceTestCase {

    public static final byte[] SALT = new byte[]{(byte) 0x02};

    @Test
    public void testHashGenerationIsDifferentWithRandomlySaltedResult() throws Exception {
        SecretKeyHashService service = new SecretKeyHashService();
        Hash one = service.generate("s3cr3t");
        Hash two = service.generate("s3cr3t");

        assertFalse(Arrays.equals(one.getHashedValue(), two.getHashedValue()));
    }

    @Test
    public void testHashGenerationIsTheSameWithFixedSalt() throws Exception {
        SecretKeyHashService service = new SecretKeyHashService();
        Hash one = service.generate("s3cr3t", SALT);
        Hash two = service.generate("s3cr3t", SALT);

        assertEquals(one.getHashedValue(), two.getHashedValue());
    }

}

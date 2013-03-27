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

import static java.lang.String.format;

import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.apache.felix.ipojo.annotations.Bind;
import org.apache.felix.ipojo.annotations.Component;
import org.apache.felix.ipojo.annotations.Provides;
import org.apache.felix.ipojo.annotations.StaticServiceProperty;
import org.apache.felix.ipojo.annotations.Unbind;
import org.osgi.framework.ServiceReference;

import com.peergreen.security.hash.Hash;
import com.peergreen.security.hash.HashException;
import com.peergreen.security.hash.HashService;
import com.peergreen.security.encode.EncoderService;
import com.peergreen.security.internal.hash.secretkey.util.References;

/**
 * @see <a href="http://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#SecretKeyFactory">Accepted algorithm names</a>
 */
@Component
@Provides(
        properties = @StaticServiceProperty(
                name = HashService.HASH_NAME_PROPERTY,
                value = "{sha-1/salt, PBKDF2WithHmacSHA1}",
                type = "java.lang.String[]"
        )
)
public class SecretKeyHashService implements HashService {

    public static final int SALT_BYTES = 24;
    public static final int HASH_BYTES = 24;
    public static final int ITERATIONS = 1000;
    public static final String DEFAULT_ALGORITHM = "PBKDF2WithHmacSHA1";

    private final SecureRandom random;
    private final SecretKeyFactory secretKeyFactory;

    private Map<String, EncoderService> encoders = new HashMap<>();

    /**
     * Default encoder service (hexa).
     */
    private EncoderService defaultEncoder;

    public SecretKeyHashService() throws Exception {
        this(DEFAULT_ALGORITHM);
    }

    public SecretKeyHashService(String algorithm) throws Exception {
        this(new SecureRandom(), algorithm);
    }

    public SecretKeyHashService(SecureRandom random, String algorithm) throws Exception {
        this(random, SecretKeyFactory.getInstance(algorithm));
    }

    public SecretKeyHashService(SecureRandom random, SecretKeyFactory factory) throws Exception {
        this.random = random;
        this.secretKeyFactory = factory;
    }

    @Bind(aggregate = true)
    public void bindEncoder(EncoderService encoder, ServiceReference<EncoderService> reference) {
        List<String> names = References.getMultiValuedProperty(reference, EncoderService.ENCODER_FORMAT);
        for (String name : names) {
            encoders.put(name, encoder);
        }
    }

    @Unbind
    public void unbindEncoder(ServiceReference<EncoderService> reference) {
        List<String> names = References.getMultiValuedProperty(reference, EncoderService.ENCODER_FORMAT);
        for (String name : names) {
            encoders.remove(name);
        }
    }

    @Bind(filter = "(encoder.format=hex)")
    public void bindDefaultEncoder(EncoderService defaultEncoder) {
        this.defaultEncoder = defaultEncoder;
    }

    @Override
    public Hash generate(String clear) {
        // Generate a random salt
        byte[] salt = new byte[SALT_BYTES];
        random.nextBytes(salt);

        return generate(clear.toCharArray(), salt, HASH_BYTES);
    }

    @Override
    public Hash generate(String clear, byte[] salt) {
        return generate(clear.toCharArray(), salt, HASH_BYTES);
    }

    @Override
    public Hash build(String encoder, String encoded) throws HashException {
        String[] segments = encoded.split(":");
        if (segments.length != 2) {
            throw new HashException(format("Expecting an input of the form '<salt>:<hash>', but was '%s'", encoded));
        }

        EncoderService encoderService;
        if (encoder != null) {
            encoderService = findEncoder(encoder);
        } else {
            encoderService = defaultEncoder;
        }
        return new SaltedHash(encoderService.decode(segments[0]), encoderService.decode(segments[1]));
    }

    private EncoderService findEncoder(String format) {
        EncoderService encoder = encoders.get(format);
        if (encoder == null) {
            throw new IllegalArgumentException(format("No registered EncoderService for format '%s'",
                                                      format
            ));
        }
        return encoder;
    }

    @Override
    public boolean validate(String clear, Hash hash) {
        if (!(hash instanceof SaltedHash)) {
            throw new IllegalArgumentException(format(
                    "Hash parameter (type:%s) has not been provided by this (%s) HashService",
                    hash.getClass().getName(),
                    this.getClass().getName()
            ));
        }
        SaltedHash salted = (SaltedHash) hash;
        Hash test = generate(clear.toCharArray(), salted.getSalt(), hash.getHashedValue().length);
        return Arrays.equals(hash.getHashedValue(), test.getHashedValue());
    }

    private Hash generate(char[] clearText, byte[] salt, int hashBytes) {
        PBEKeySpec spec = new PBEKeySpec(clearText, salt, ITERATIONS, hashBytes * 8);
        try {
            SecretKey secretKey = secretKeyFactory.generateSecret(spec);
            return new SaltedHash(secretKey.getEncoded(), salt, DEFAULT_ALGORITHM);
        } catch (InvalidKeySpecException e) {
            // Should never happen
            throw new IllegalStateException(e);
        } finally {
            spec.clearPassword();
        }
    }

}

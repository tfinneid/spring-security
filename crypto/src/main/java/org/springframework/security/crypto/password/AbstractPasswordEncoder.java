/*
 * Copyright 2002-2016 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.crypto.password;

import java.security.MessageDigest;

import org.springframework.security.crypto.codec.Hex;
import org.springframework.security.crypto.keygen.BytesKeyGenerator;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.crypto.util.EncodingUtils;

/**
 * Abstract base class for password encoders
 *
 * @author Rob Worsnop
 */
public abstract class AbstractPasswordEncoder implements PasswordEncoder {

	private final BytesKeyGenerator saltGenerator;

	protected AbstractPasswordEncoder() {
		this.saltGenerator = KeyGenerators.secureRandom();
	}

	public String encode(CharSequence rawPassword) {
		return encode(rawPassword.toString().toCharArray());
	}

	@Override
	public String encode(char[] rawPassword) {
		byte[] salt = this.saltGenerator.generateKey();
		byte[] encoded = encodeAndConcatenate(rawPassword, salt);
		return String.valueOf(Hex.encode(encoded));
	}

	public boolean matches(CharSequence rawPassword, String encodedPassword) {
		return matches(rawPassword.toString().toCharArray(), encodedPassword);
	}

	@Override
	public boolean matches(char[] rawPassword, String encodedPassword) {
		byte[] digested = Hex.decode(encodedPassword);
		byte[] salt = EncodingUtils.subArray(digested, 0, this.saltGenerator.getKeyLength());
		return matches(digested, encodeAndConcatenate(rawPassword, salt));
	}

	protected abstract byte[] encode(char[] rawPassword, byte[] salt);

	protected byte[] encodeAndConcatenate(char[] rawPassword, byte[] salt) {
		return EncodingUtils.concatenate(salt, encode(rawPassword, salt));
	}

	/**
	 * Constant time comparison to prevent against timing attacks.
	 */
	protected static boolean matches(byte[] expected, byte[] actual) {
		return MessageDigest.isEqual(expected, actual);
	}

}

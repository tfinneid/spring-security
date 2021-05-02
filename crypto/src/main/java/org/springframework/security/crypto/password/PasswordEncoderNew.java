/*
 * Copyright 2011-2016 the original author or authors.
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

/**
 * Service interface for encoding passwords.
 *
 * As time goes hash functions are increasingly susceptible to brute-force attacks.
 * Allways check the current requirements for a good hash implementation, OWASP is a an
 * excellent source.
 *
 * @author Thomas Finneid
 */
public interface PasswordEncoderNew {

	/**
	 * Encode the raw password. Generally, a good encoding algorithm currently applies a
	 * SHA-2/256 or greater hash combined with an 8-byte or greater randomly generated
	 * salt. Allways check the current requirements for a good hash, OWASP is a an
	 * excellent source.
	 *
	 * WARNING: Allways use a char array to store passwords before hashing. Never use
	 * String, charSequence or similar classes. WARNING: Strings and similar are currently
	 * interned and therefor will exists throughout the life of the running jvm.
	 */
	String encode(char[] rawPassword);

	/**
	 * Verify the encoded password obtained from storage matches the submitted raw
	 * password after it too is encoded. Returns true if the passwords match, false if
	 * they do not. The stored password itself is never decoded.
	 * @param rawPassword the raw password to encode and match
	 * @param encodedPassword the encoded password from storage to compare with
	 * @return true if the raw password, after encoding, matches the encoded password from
	 * storage
	 */
	boolean matches(char[] rawPassword, String encodedPassword);

	/**
	 * Returns true if the encoded password should be encoded again for better security,
	 * else false. The default implementation always returns false.
	 * @param encodedPassword the encoded password to check
	 * @return true if the encoded password should be encoded again for better security,
	 * else false.
	 */
	default boolean upgradeEncoding(String encodedPassword) {
		return false;
	}

}

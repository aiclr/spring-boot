/*
 * Copyright 2012-2020 the original author or authors.
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

package org.springframework.boot.loader;

public final class DefaultTools implements DecryptClassTool {

	private static volatile DefaultTools INSTANCE;

	private DefaultTools() {

	}

	public static DefaultTools getInstance() {
		if (INSTANCE == null) {
			synchronized (DefaultTools.class) {
				if (INSTANCE == null) {
					INSTANCE = new DefaultTools();
				}
			}
		}
		return INSTANCE;
	}

	@Override
	public byte[] decode(byte[] ciphertext, byte[] plaintext, int bytesRead) {
		for (int i = 0; i < bytesRead; i++) {
			plaintext[i] = (byte) (ciphertext[i] ^ 1);
		}
		return plaintext;
	}

}

/* 
 * Copyright 2008 The Apache Software Foundation or its licensors, as
 * applicable.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * A licence was granted to the ASF by Florian Sager on 30 November 2008
 */
package de.agitos.dkim;

import java.io.IOException;

/*
 * Provides Simple and Relaxed Canonicalization according to DKIM RFC 4871.
 * 
 * @author Florian Sager, http://www.agitos.de, 22.11.2008
 */

public class Canonicalization {
	
	public static Canonicalization SIMPLE = new Canonicalization() {
		
		public String getType() {
			
			return "simple";
		}
		
		public String canonicalizeHeader(String name, String value) {
			
			return name+":"+value;
		}
		
		public String canonicalizeBody(String body) throws IOException {

			if (body == null || "".equals(body) ) {
				return "\r\n";
			}

			// The body must end with \r\n
			if (!"\r\n".equals(body.substring(body.length()-2, body.length()))) {
				return body+"\r\n";
			}

			// Remove trailing empty lines ...
			while ("\r\n\r\n".equals(body.substring(body.length()-4, body.length()))) {
				body = body.substring(0, body.length()-2);
			}

			return body;
		}
	};
	
	public static Canonicalization RELAXED = new Canonicalization() {

		public String getType() {
			
			return "relaxed";
		}
		
		public String canonicalizeHeader(String name, String value) {
			
			name = name.trim().toLowerCase();
			value = value.replaceAll("\\s+", " ").trim();
			return name+":"+value;
		}
		
		public String canonicalizeBody(String body) throws IOException {
			
			if (body == null || "".equals(body) ) {
				return "\r\n";
			}

			body = body.replaceAll("[ \\t\\x0B\\f]+", " ");
			body = body.replaceAll(" \r\n", "\r\n");

			// The body must end with \r\n
			if (!"\r\n".equals(body.substring(body.length()-2, body.length()))) {
				return body+"\r\n";
			}

			// Remove trailing empty lines ...
			while ("\r\n\r\n".equals(body.substring(body.length()-4, body.length()))) {
				body = body.substring(0, body.length()-2);
			}

			return body;
		}
	};

	public Canonicalization() { }
	
	public String getType() {
		return "unknown";
	}
	
	public String canonicalizeHeader(String name, String value) {
		return null;
	}
	
	public String canonicalizeBody(String body) throws IOException {
		return null;
	}
}

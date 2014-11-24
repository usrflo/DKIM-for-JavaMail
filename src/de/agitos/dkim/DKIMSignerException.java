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

/*
 * @author Florian Sager, http://www.agitos.de, 15.11.2008
 */

public class DKIMSignerException extends Exception {
	
	public DKIMSignerException(String message) {
		super(message);
	}
	
	public DKIMSignerException(String message, Exception e) {
		super(message, e);
	}

}

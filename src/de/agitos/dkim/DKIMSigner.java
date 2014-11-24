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

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.Map.Entry;

import javax.mail.MessagingException;

import com.sun.mail.util.CRLFOutputStream;


/*
 * Main class providing a signature according to DKIM RFC 4871.
 * 
 * @author Florian Sager, http://www.agitos.de, 15.10.2008
 */

public class DKIMSigner {

	private static String DKIMSIGNATUREHEADER = "DKIM-Signature";
	private static int MAXHEADERLENGTH = 67;

	private static ArrayList<String> minimumHeadersToSign = new ArrayList<String>();
	static {
		minimumHeadersToSign.add("From");
		minimumHeadersToSign.add("To");
		minimumHeadersToSign.add("Subject");
	}
	
	private String[] defaultHeadersToSign = new String[]{
			"Content-Description","Content-ID","Content-Type","Content-Transfer-Encoding","Cc",
			"Date","From","In-Reply-To","List-Subscribe","List-Post","List-Owner","List-Id",
			"List-Archive","List-Help","List-Unsubscribe","MIME-Version","Message-ID","Resent-Sender",
			"Resent-Cc","Resent-Date","Resent-To","Reply-To","References","Resent-Message-ID",
			"Resent-From","Sender","Subject","To"};

	private SigningAlgorithm signingAlgorithm = SigningAlgorithm.SHA256withRSA; // use rsa-sha256 by default, see RFC 4871
	private Signature signatureService;
	private MessageDigest messageDigest;
	private String signingDomain;
	private String selector;
	private String identity = null;
	private boolean lengthParam = false;
	private boolean zParam = false;
	private Canonicalization headerCanonicalization = Canonicalization.RELAXED;
	private Canonicalization bodyCanonicalization = Canonicalization.SIMPLE;
	private PrivateKey privkey;

	public DKIMSigner(String signingDomain, String selector, PrivateKey privkey) throws Exception {
		initDKIMSigner(signingDomain, selector, privkey);
	}

	public DKIMSigner(String signingDomain, String selector, String privkeyFilename) throws Exception {

		File privKeyFile = new File(privkeyFilename);

		// read private key DER file
        DataInputStream dis = new DataInputStream(new FileInputStream(privKeyFile));
		byte[] privKeyBytes = new byte[(int) privKeyFile.length()];
		dis.read(privKeyBytes);
		dis.close();

		KeyFactory keyFactory = KeyFactory.getInstance("RSA");

		// decode private key
		PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(privKeyBytes);
		RSAPrivateKey privKey = (RSAPrivateKey) keyFactory.generatePrivate(privSpec);

		initDKIMSigner(signingDomain, selector, privKey);
	}

	private void initDKIMSigner(String signingDomain, String selector, PrivateKey privkey) throws DKIMSignerException {

		if (!DKIMUtil.isValidDomain(signingDomain)) {
			throw new DKIMSignerException(signingDomain+" is an invalid signing domain");
		}

		this.signingDomain = signingDomain;
		this.selector = selector.trim();
		this.privkey = privkey;
		this.setSigningAlgorithm(this.signingAlgorithm);
	}

	public String getIdentity() {
		return identity;
	}

	public void setIdentity(String identity) throws DKIMSignerException {

		if (identity!=null) {
			identity = identity.trim();
			if (!identity.endsWith("@"+signingDomain) && !identity.endsWith("."+signingDomain)) {
				throw new DKIMSignerException("The domain part of "+identity+" has to be "+signingDomain+" or its subdomain");
			}
		}

		this.identity = identity;
	}

	public Canonicalization getBodyCanonicalization() {
		return bodyCanonicalization;
	}

	public void setBodyCanonicalization(Canonicalization bodyCanonicalization) throws DKIMSignerException {
		this.bodyCanonicalization = bodyCanonicalization;
	}

	public Canonicalization getHeaderCanonicalization() {
		return headerCanonicalization;
	}

	public void setHeaderCanonicalization(Canonicalization headerCanonicalization) throws DKIMSignerException {
		this.headerCanonicalization = headerCanonicalization;
	}

	public String[] getDefaultHeadersToSign() {
		return defaultHeadersToSign;
	}

	public void addHeaderToSign(String header) {

		if (header==null || "".equals(header)) return;
		
		int len = this.defaultHeadersToSign.length;
		String[] headersToSign = new String[len+1];
		for (int i=0; i<len; i++) {
			if (header.equals(this.defaultHeadersToSign[i])) {
				return;
			}
			headersToSign[i] = this.defaultHeadersToSign[i];
		}
		
		headersToSign[len] = header;
		
		this.defaultHeadersToSign = headersToSign;
	}
	
	public void removeHeaderToSign(String header) {
		
		if (header==null || "".equals(header)) return;
		
		int len = this.defaultHeadersToSign.length;
		if (len==0) return;
		
		String[] headersToSign = new String[len-1];
		
		int found = 0;
		for (int i=0; i<len-1; i++) {
			
			if (header.equals(this.defaultHeadersToSign[i+found])) {
				found = 1;
			}
			headersToSign[i] = this.defaultHeadersToSign[i+found];
		}
		
		this.defaultHeadersToSign = headersToSign;
	}
	
	public void setLengthParam(boolean lengthParam) {
		this.lengthParam = lengthParam;
	}
	
	public boolean getLengthParam() {
		return lengthParam;
	}

	public boolean isZParam() {
		return zParam;
	}

	public void setZParam(boolean param) {
		zParam = param;
	}

	public SigningAlgorithm getSigningAlgorithm() {
		return signingAlgorithm;
	}

	public void setSigningAlgorithm(SigningAlgorithm signingAlgorithm) throws DKIMSignerException {

		try {
			this.messageDigest = MessageDigest.getInstance(signingAlgorithm.getJavaHashNotation());
		} catch (NoSuchAlgorithmException nsae) {
			throw new DKIMSignerException("The hashing algorithm "+signingAlgorithm.getJavaHashNotation()+" is not known by the JVM", nsae);
		}
		
		try {
			this.signatureService = Signature.getInstance(signingAlgorithm.getJavaSecNotation());
		} catch (NoSuchAlgorithmException nsae) {
			throw new DKIMSignerException("The signing algorithm "+signingAlgorithm.getJavaSecNotation()+" is not known by the JVM", nsae);
		}
		
		try {
			this.signatureService.initSign(privkey);
		} catch (InvalidKeyException ike) {
			throw new DKIMSignerException("The provided private key is invalid", ike);
		}
		
		this.signingAlgorithm = signingAlgorithm;
	}

	private String serializeDKIMSignature(Map<String, String> dkimSignature) {

		Set<Entry<String, String>> entries = dkimSignature.entrySet();
		StringBuffer buf = new StringBuffer(), fbuf;
		int pos = 0;

		Iterator<Entry<String, String>> iter = entries.iterator();
		while (iter.hasNext()) {
			Entry<String, String> entry = iter.next();

			// buf.append(entry.getKey()).append("=").append(entry.getValue()).append(";\t");
			
			fbuf = new StringBuffer();
			fbuf.append(entry.getKey()).append("=").append(entry.getValue()).append(";");
			
			if (pos + fbuf.length() + 1 > MAXHEADERLENGTH) {
				
				pos = fbuf.length();

				// line folding : this doesn't work "sometimes" --> maybe someone likes to debug this 
				/* int i = 0;
				while (i<pos) {
					if (fbuf.substring(i).length()>MAXHEADERLENGTH) {
						buf.append("\r\n\t").append(fbuf.substring(i, i+MAXHEADERLENGTH));
						i += MAXHEADERLENGTH;
					} else {
						buf.append("\r\n\t").append(fbuf.substring(i));
						pos -= i;
						break;
					}
				} */
				
				buf.append("\r\n\t").append(fbuf);

			} else {
				buf.append(" ").append(fbuf);
				pos += fbuf.length() + 1;
			}
		}

		buf.append("\r\n\tb=");

		return buf.toString().trim();
	}
	
	private String foldSignedSignature(String s, int offset) {
		
		int i = 0;
		StringBuffer buf = new StringBuffer();

		while (true) {
			if (offset > 0 && s.substring(i).length()>MAXHEADERLENGTH - offset) {
				buf.append(s.substring(i, i + MAXHEADERLENGTH - offset));
				i += MAXHEADERLENGTH - offset;
				offset = 0;
			} else if (s.substring(i).length()>MAXHEADERLENGTH) {
				buf.append("\r\n\t").append(s.substring(i, i + MAXHEADERLENGTH));
				i += MAXHEADERLENGTH;
			} else {
				buf.append("\r\n\t").append(s.substring(i));
				break;
			}
		}
		
		return buf.toString();
	}

	public String sign(SMTPDKIMMessage message) throws DKIMSignerException, MessagingException {

		Map<String, String> dkimSignature = new LinkedHashMap<String, String>();
		dkimSignature.put("v", "1");
		dkimSignature.put("a", this.signingAlgorithm.getRfc4871Notation());
		dkimSignature.put("q", "dns/txt");
		dkimSignature.put("c", getHeaderCanonicalization().getType()+"/"+getBodyCanonicalization().getType());  
		dkimSignature.put("t", ((long) new Date().getTime() / 1000)+"");
		dkimSignature.put("s", this.selector);
		dkimSignature.put("d", this.signingDomain);

		// set identity inside signature
		if (identity!=null) {
			dkimSignature.put("i", DKIMUtil.QuotedPrintable(identity));
		}

		// process header
		ArrayList assureHeaders = (ArrayList) minimumHeadersToSign.clone();

		// intersect defaultHeadersToSign with available headers
		StringBuffer headerList = new StringBuffer();
		StringBuffer headerContent = new StringBuffer();
		StringBuffer zParamString = new StringBuffer();

		Enumeration headerLines = message.getMatchingHeaderLines(defaultHeadersToSign);
		while (headerLines.hasMoreElements()) {
			String header = (String) headerLines.nextElement();
			String[] headerParts = DKIMUtil.splitHeader(header);
			headerList.append(headerParts[0]).append(":");
			headerContent.append(this.headerCanonicalization.canonicalizeHeader(headerParts[0], headerParts[1])).append("\r\n");
			assureHeaders.remove(headerParts[0]);

			// add optional z= header list, DKIM-Quoted-Printable
			if (this.zParam) {
				zParamString.append(headerParts[0]).append(":").append(DKIMUtil.QuotedPrintable(headerParts[1].trim()).replace("|", "=7C")).append("|");
			}
		}

		if (!assureHeaders.isEmpty()) {
			throw new DKIMSignerException("Could not find the header fields "+DKIMUtil.concatArray(assureHeaders, ", ")+" for signing");
		}

		dkimSignature.put("h", headerList.substring(0, headerList.length()-1));

		if (this.zParam) {
			String zParamTemp = zParamString.toString();
			dkimSignature.put("z", zParamTemp.substring(0, zParamTemp.length()-1));
		}

		// process body
		String body = message.getEncodedBody(); 
		ByteArrayOutputStream baos = new ByteArrayOutputStream(); 
		CRLFOutputStream crlfos = new CRLFOutputStream(baos); 
		try { 
			crlfos.write(body.getBytes()); 
		} catch (IOException e) { 
			throw new DKIMSignerException("The body conversion to MIME canonical CRLF line terminator failed", e); 
		} 
		body = baos.toString(); 
		
		try {
			body = this.bodyCanonicalization.canonicalizeBody(body);
		} catch (IOException ioe) {
			throw new DKIMSignerException("The body canonicalization failed", ioe);
		}

		if (this.lengthParam) {
			dkimSignature.put("l", body.length()+"");
		}

		// calculate and encode body hash
		dkimSignature.put("bh", DKIMUtil.base64Encode(this.messageDigest.digest(body.getBytes())));

		// create signature
		String serializedSignature = serializeDKIMSignature(dkimSignature);

		byte[] signedSignature;
		try {
			signatureService.update(headerContent.append(this.headerCanonicalization.canonicalizeHeader(DKIMSIGNATUREHEADER, " "+serializedSignature)).toString().getBytes());
			signedSignature = signatureService.sign();
		} catch (SignatureException se) {
			throw new DKIMSignerException("The signing operation by Java security failed", se);
		}

		return DKIMSIGNATUREHEADER + ": " + serializedSignature+foldSignedSignature(DKIMUtil.base64Encode(signedSignature), 3);
	}
}

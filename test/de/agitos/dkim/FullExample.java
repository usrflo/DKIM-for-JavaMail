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

import java.util.Properties;

import javax.mail.Message;
import javax.mail.Multipart;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMultipart;

/* 
 * This example sends a DKIM signed email with standard signature configuration.
 * This version of DKIM for JavaMail was tested with JavaMail 1.4.1, downward compatibility with 1.3 is expected.
 * 
 * @author Florian Sager, http://www.agitos.de, 22.11.2008
 */

public class FullExample {

	public static void main(String args[]) throws Exception {

		// read test configuration from test.properties in your classpath
		Properties testProps = TestUtil.readProperties();

		// get a JavaMail Session object 
		Session session = Session.getDefaultInstance(testProps, null);

		
		
		///////// beginning of DKIM FOR JAVAMAIL stuff
		
		// get DKIMSigner object
		DKIMSigner dkimSigner = new DKIMSigner(
				testProps.getProperty("mail.smtp.dkim.signingdomain"),
				testProps.getProperty("mail.smtp.dkim.selector"),
				testProps.getProperty("mail.smtp.dkim.privatekey"));

		/* set an address or user-id of the user on behalf this message was signed;
		 * this identity is up to you, except the domain part must be the signing domain
		 * or a subdomain of the signing domain.
		 */ 
		dkimSigner.setIdentity("fullexample@"+testProps.getProperty("mail.smtp.dkim.signingdomain"));
		
		// get default
		System.out.println("Default headers getting signed if available:");
		TestUtil.printArray(dkimSigner.getDefaultHeadersToSign());

		// the following header will be signed as well if available
		dkimSigner.addHeaderToSign("ASpecialHeader");
		
		// the following header won't be signed
		dkimSigner.removeHeaderToSign("Content-Type");

		// change default canonicalizations
		dkimSigner.setHeaderCanonicalization(Canonicalization.SIMPLE);
		dkimSigner.setBodyCanonicalization(Canonicalization.RELAXED);

		// add length param to the signature, see RFC 4871
		dkimSigner.setLengthParam(true);
		
		// change default signing algorithm
		dkimSigner.setSigningAlgorithm(SigningAlgorithm.SHA1withRSA);

		// add a list of header=value pairs to the signature for debugging reasons 
		dkimSigner.setZParam(true);

		///////// end of DKIM FOR JAVAMAIL stuff
		
		
		

		// construct the JavaMail message using the DKIM message type from DKIM for JavaMail
		Message msg = new SMTPDKIMMessage(session, dkimSigner);
		Multipart mp = new MimeMultipart();
		msg.setFrom(new InternetAddress(testProps.getProperty("mail.smtp.from")));
		if (testProps.getProperty("mail.smtp.to") != null) {
			msg.setRecipients(Message.RecipientType.TO,
					InternetAddress.parse(testProps.getProperty("mail.smtp.to"), false));
		}
		if (testProps.getProperty("mail.smtp.cc") != null) {
			msg.setRecipients(Message.RecipientType.CC,
					InternetAddress.parse(testProps.getProperty("mail.smtp.cc"), false));
		}

		msg.setSubject("DKIM for JavaMail: FullExample Testmessage");
		
		MimeBodyPart mbp_msgtext = new MimeBodyPart();
        mbp_msgtext.setText(TestUtil.bodyText);
        mp.addBodyPart(mbp_msgtext);
        
        TestUtil.addFileAttachment(mp, testProps.get("mail.smtp.attachment"));
        
        msg.setContent(mp);

        // send the message by JavaMail
		Transport transport = session.getTransport("smtp"); // or smtps ( = TLS)
		transport.connect(testProps.getProperty("mail.smtp.host"),
				testProps.getProperty("mail.smtp.auth.user"),
				testProps.getProperty("mail.smtp.auth.password"));
		transport.sendMessage(msg, msg.getAllRecipients());
		transport.close();
	}
}

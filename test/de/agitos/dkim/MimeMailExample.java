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

import java.io.ByteArrayInputStream;
import java.util.Date;
import java.util.Properties;

import javax.mail.Message;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.MailDateFormat;

/* 
 * This example signs and sends an existing email with standard DKIM signature configuration.
 * This version of DKIM for JavaMail was tested with JavaMail 1.4.1, downward compatibility with 1.3 is expected.
 * 
 * @author Florian Sager, http://www.agitos.de, 10.05.2009
 */

public class MimeMailExample {

	public static void main(String args[]) throws Exception {
		
		// read test configuration from test.properties in your classpath
		Properties testProps = TestUtil.readProperties();
		
		// generate string buffered test mail
		StringBuffer mimeMail = new StringBuffer();
		mimeMail.append("Date: ").append(new MailDateFormat().format(new Date())).append("\r\n");
		mimeMail.append("From: ").append(testProps.getProperty("mail.smtp.from")).append("\r\n");
		mimeMail.append("To: ").append(testProps.getProperty("mail.smtp.to")).append("\r\n");
		mimeMail.append("Subject: ").append("DKIM for JavaMail: MimeMailExample Testmessage").append("\r\n");
		mimeMail.append("\r\n");
		mimeMail.append(TestUtil.bodyText);

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
		dkimSigner.setIdentity("mimemailexample@"+testProps.getProperty("mail.smtp.dkim.signingdomain"));

		// construct the JavaMail message using the DKIM message type from DKIM for JavaMail
		Message msg = new SMTPDKIMMessage(session, new ByteArrayInputStream(mimeMail.toString().getBytes()), dkimSigner);

		///////// end of DKIM FOR JAVAMAIL stuff

		// send the message by JavaMail
		Transport transport = session.getTransport("smtp");
		transport.connect(testProps.getProperty("mail.smtp.host"),
				testProps.getProperty("mail.smtp.auth.user"),
				testProps.getProperty("mail.smtp.auth.password"));
		transport.sendMessage(msg, msg.getAllRecipients());
		transport.close();
	}
}

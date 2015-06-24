package com.simonmoffatt.forgerock.openam.authentication.jdbc;

//import com.sun.identity.authentication.modules.jdbc.JDBCPasswordSyntaxTransform;
import com.sun.identity.authentication.spi.AuthLoginException;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * A very simple implementation of the JDBC Password Syntax Transform what generates a SHA1 hash of a clear text input
 */
public class SHA1Transform implements com.sun.identity.authentication.modules.jdbc.JDBCPasswordSyntaxTransform {

	public SHA1Transform() {
	}

	/**
	 * This simply returns the SHA1 hash of the input
	 * 
	 * @param input Password before transform
	 * @return Password after transform in this case, a SHA1 hash
	 * @throws AuthLoginException
	 */

	// Takes the clear text and returns a SHA1 representation
	public String transform(String input) throws AuthLoginException {
		
		String SHA1Password = "";
		
		if (input == null) {
			throw new AuthLoginException(
					"No input to the Clear Text Transform!");
		}
		
		MessageDigest mDigest;
		try {
			mDigest = MessageDigest.getInstance("SHA1");
			byte[] result = mDigest.digest(input.getBytes());
			StringBuffer sb = new StringBuffer();
			for (int i = 0; i < result.length; i++) {
				sb.append(Integer.toString((result[i] & 0xff) + 0x100, 16).substring(1));
			}

			SHA1Password = sb.toString();

		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return SHA1Password;
	}
}

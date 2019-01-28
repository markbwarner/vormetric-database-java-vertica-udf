/* Copyright (c) 2005 - 2014, Hewlett-Packard Development Co., L.P.  -*- Java -*-*/
/* 
 *
 * Description: Example User Defined Scalar Function: Add 2 ints
 *
 * Create Date: June 1, 2013
 */

package com.vertica.JavaLibs;

import com.vertica.sdk.*;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.io.*;
import java.nio.charset.*;

import sun.security.pkcs11.wrapper.*;
import static sun.security.pkcs11.wrapper.PKCS11Constants.*;
import sun.security.pkcs11.Secmod.*;

public class VormetricDecryptFunction extends ScalarFunctionFactory {

	public static final byte[] iv = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x0A, 0x0B, 0x0C,
			0x0D, 0x0E, 0x0F };
	public static final CK_MECHANISM encMechCbcPad = new CK_MECHANISM(CKM_AES_CBC_PAD, iv);
	public static final CK_MECHANISM encMechCtr = new CK_MECHANISM(CKM_AES_CTR, iv);
	public static final CK_MECHANISM encMechCbc = new CK_MECHANISM(CKM_AES_CBC, iv);

	public static final String plainTextInp = "Plain text message to be encrypted.";

	// public void VormetricEncrypt()
	// {
	// vol = ScalarFunctionFactory.volatility.IMMUTABLE;

	// }

	@Override
	public void getPrototype(ServerInterface srvInterface, ColumnTypes argTypes, ColumnTypes returnType) {
		// field name is column to encrypt
		argTypes.addVarchar();
		argTypes.addVarchar();
		// field name operation
		returnType.addVarchar();

	}

	public class VormetricDecryptData extends ScalarFunction {
		// note took out override...

		String raw_text;

		StringBuffer numberPattern = new StringBuffer("0123456789");
		StringBuffer stringPattern = new StringBuffer("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ");
		StringBuffer combinedPattern =new StringBuffer("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789");
	
        String utfMode = "ASCII";	
        
		String pin = "yourpwd";
		String libPath = null;
		String operation = "CBC_PAD";
		String charSetStr = "0123456789-";
		String charSetInputFile = null;
		String keyName = "vpkcs11_java_test_key";

		byte[] tweak = { 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00 };
		CK_MECHANISM encMechFpe = null;
		CK_MECHANISM encMech = null;
		Vpkcs11Session session = Helper.startUp(Helper.getPKCS11LibPath(libPath), pin);
		long keyID = Helper.findKey(session, keyName);

		public void setup(ServerInterface srvInterface, SizedColumnTypes argTypes) {

			if (keyID == 0) {
				srvInterface.log("the key is not found, creating it...");
				keyID = Helper.createKey(session, keyName);
				srvInterface.log("Key successfully Created. Key Handle: " + keyID);
			} else {
				srvInterface.log("Key successfully Found. Key Handle: " + keyID);
			}

		}

		public void destroy(ServerInterface srvInterface, SizedColumnTypes argTypes) {
			Helper.closeDown(session);
			srvInterface.log("End EncryptDecryptMessage.");

		}

		public void processBlock(ServerInterface srvInterface, BlockReader arg_reader, BlockWriter res_writer)
				throws UdfException, DestroyInvocation {

			do {
				String raw_text = arg_reader.getString(0);
							
				String operation = arg_reader.getString(1);

/*				if (operation.equalsIgnoreCase("CBC") || operation.equalsIgnoreCase("CBC_PAD")
						|| operation.equalsIgnoreCase("FPE") || operation.equalsIgnoreCase("CTR")) {
					// Valid operation.
				} else
					operation = "CBC_PAD";
				
				if (operation.equalsIgnoreCase("CBC") || operation.equalsIgnoreCase("FPE")) {
					if (raw_text != null && raw_text.length() > 0) {
						int inputlen = raw_text.length();
						if (inputlen < 2)
							raw_text = raw_text + " ";
					} else {
						raw_text = "null";
					}

				}
				
				String input_without_sc = raw_text.replaceAll(
						"[\\ \\;\\/\\=\\<\\>\\`\\|\\}\\{\\_\\~\\@\\*\\(\\)\\'\\&\\%\\$\\#\\!\\?\\-\\+\\.\\^:,]", "");
				
				srvInterface.log("result = " + input_without_sc);*/
			
				//String sc = getSCUnique(raw_text);
				// int cnt = getSpecialCharacterCount(s);
		//		srvInterface.log("sc = " + sc);

/*				boolean b = isNumeric(input_without_sc);
				if (b) {
					 
					numberPattern.append(sc);
					srvInterface.log("number pattern = " + numberPattern.toString().trim());
					charSetStr = numberPattern.toString();
				} else {
					b = isAlpha(input_without_sc);
					if (b) {
					
						stringPattern.append(sc);
						srvInterface.log("alpha pattern = " + stringPattern.toString().trim());
						charSetStr = stringPattern.toString();
					} else {
						
						combinedPattern.append(sc);
						srvInterface.log("combined pattern = " + combinedPattern.toString().trim());
						charSetStr = combinedPattern.toString();
					}
				}*/
				

				byte[] plainBytes;
				int plainBytesLen;
				boolean valid_nbr = true;

				srvInterface.log("Start EncryptDecryptMessage ...");
				int i;

				String plainText, decryptedText = "";

				long nbrofrows = 0;
				if (valid_nbr) {

					if (operation.equals("CTR")) {
						srvInterface.log("CTR mode selected");
						encMech = encMechCtr;

					} else if (operation.equals("FPE")) {
						srvInterface.log("FPE mode selected");

						byte[] charSet = charSetStr != null ? charSetStr.getBytes() : "0123456789".getBytes();

						ByteArrayOutputStream fpeIVBytes = new ByteArrayOutputStream(9 + charSet.length);
						DataOutputStream dos = new DataOutputStream(fpeIVBytes);

						try {
							dos.write(tweak, 0, 8);
							dos.write((charSetStr != null ? charSet.length : 1) & 0xFF);
							dos.write(charSet, 0, charSet.length);
							dos.flush();
						} catch (IOException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}

						encMechFpe = new CK_MECHANISM(0x80004001L, fpeIVBytes.toByteArray());

						encMech = encMechFpe;
					} else if (operation.equals("CBC")) {
						srvInterface.log("CBC mode selected");
						encMech = encMechCbc;
					} else {
						srvInterface.log("CBC PAD mode selected");
						encMech = encMechCbcPad;
					}

					/* encrypt, decrypt with key */

					plainBytes = raw_text.getBytes();
					decryptedText = encryptDecryptBuf(session, encMech, keyID, plainBytes, srvInterface);

				}

				res_writer.setString(decryptedText);

				res_writer.next();

			} while (arg_reader.next());

		}

	}

	/***
	 * @Override public void getReturnType(ServerInterface srvInterface,
	 *           SizedColumnTypes argTypes, SizedColumnTypes returnType) {
	 *           returnType.addVarchar(argTypes.getColumnType(0).getStringLength(),
	 *           argTypes.getColumnName(0)); }
	 */
	@Override
	public void getReturnType(ServerInterface srvInterface, SizedColumnTypes argTypes, SizedColumnTypes returnType) {
		returnType.addVarchar((argTypes.getColumnType(0).getStringLength() + 200) * 2, argTypes.getColumnName(0));
	}

	// returnType.addVarchar(
	// (argTypes.getColumnType(0).getStringLength() + 200) * 2,
	// argTypes.getColumnName(0));

	@Override
	public ScalarFunction createScalarFunction(ServerInterface srvInterface) {
		return new VormetricDecryptData();
	}
	
	public static boolean isNumeric(String str) {
		// StringBuffer specialchar = new StringBuffer();
		for (char c : str.toCharArray()) {

			if (!Character.isDigit(c)) {
				System.out.println(c);
				return false;
			}
		}
		return true;
	}
	
	public static boolean isAlpha(String str) {
		 
		for (char c : str.toCharArray()) {

			if (!Character.isAlphabetic(c)) {
				System.out.println(c);
				return false;
			}
		}
		return true;
				
	}
	
	public static String getSCUnique(String name) {
		StringBuffer returnvalue = new StringBuffer();
		HashMap hm = new HashMap();
		String specialCharacters = " !#$%&'()*+,-./:;<=>?@[]^_`{|}~";
		//String specialCharacters = " !#$%&'()*+,-./:;<=>?@^_`{|}~";
		String str2[] = name.split("");
		int count = 0;
		for (int i = 0; i < str2.length; i++) {
			if (specialCharacters.contains(str2[i])) {
				count++;
				hm.put(str2[i], str2[i]);
			
			}

		}
		
		
		Set set = hm.entrySet();
		 Iterator i = set.iterator();
	      
	      // Display elements
	      while(i.hasNext()) {
	         Map.Entry me = (Map.Entry)i.next();
	         //System.out.print(me.getKey() + ": ");
	         //System.out.println(me.getValue());
	         returnvalue.append(me.getKey());	      }

		//System.out.println("spcecial char " + returnvalue.toString());
		return returnvalue.toString();
	}

	public String encryptDecryptBuf(Vpkcs11Session session, CK_MECHANISM encMech, long keyID, byte[] plainBytes,
			ServerInterface srvInterface) {
		try {
			byte[] encryptedText;
			byte[] decryptedText;
			int encryptedDataLen = 0;
			int decryptedDataLen = 0;
			byte[] outText = {};
	        String utfMode = "ASCII";	
			 byte[] decryptedBytes;
			 

			int plainBytesLen = plainBytes.length;
			srvInterface.log("plaintext byte length: " + plainBytesLen);

	
				
			//session.p11.C_EncryptInit(session.sessionHandle, encMech, keyID);
		//	srvInterface.log("C_DecryptInit success.");

		//	encryptedDataLen = session.p11.C_Encrypt(session.sessionHandle, plainBytes, 0, plainBytesLen, outText, 0,
		//			0);
		//	srvInterface.log("C_Encrypt success. Encrypted data len = " + encryptedDataLen);

			
			
			session.p11.C_DecryptInit(session.sessionHandle, encMech, keyID);
			srvInterface.log("C_DecryptInit success.");

			decryptedDataLen = session.p11.C_Decrypt(session.sessionHandle, plainBytes, 0, plainBytesLen,
					outText, 0, 0);
			
			//encryptedText = new byte[decryptedDataLen];
			
			srvInterface.log("C_Decrypt success. Decrypted data length = " + decryptedDataLen);

			decryptedText = new byte[decryptedDataLen];
			decryptedDataLen = session.p11.C_Decrypt(session.sessionHandle, plainBytes, 0, plainBytes.length,
					decryptedText, 0, decryptedDataLen);
			srvInterface.log("C_Decrypt 2nd call succeed. Decrypted data length = " + decryptedDataLen);

			 decryptedBytes = new byte[decryptedDataLen];
             System.arraycopy(decryptedText, 0, decryptedBytes, 0, decryptedDataLen);

             String decryptedTextStr = new String(decryptedBytes, Charset.forName(utfMode));
             
			//String decryptedTextStr = new String(decryptedText, 0, decryptedDataLen);
			String plainTextStr = new String(plainBytes);

			srvInterface.log("Plaintext = " + plainTextStr);
			srvInterface.log("Decrypted Text New Code = " + decryptedTextStr);
			

             

			return decryptedTextStr;

		} catch (PKCS11Exception e) {
			e.printStackTrace();
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		return null;
	}

}

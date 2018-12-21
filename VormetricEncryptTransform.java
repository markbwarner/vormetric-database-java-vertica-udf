/* Copyright (c) 2005 - 2014, Hewlett-Packard Development Co., L.P.  -*- Java -*-*/
/* 
 * Description: Example User Defined Transform Function: Output top-k rows in each partition
 *
 * Create Date: June 1, 2013
 */

package com.vertica.JavaLibs;


import com.vertica.sdk.*;

import java.io.*;
import java.nio.charset.*;
import java.nio.file.*;
import java.security.*;
import java.util.*;

import sun.security.pkcs11.wrapper.*;
import static sun.security.pkcs11.wrapper.PKCS11Constants.*;
import sun.security.pkcs11.Secmod.*;

// TopK per partition
public class VormetricEncryptTransform extends TransformFunctionFactory {

	
	public static final byte[] iv = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
	public static final CK_MECHANISM encMechCbcPad = new CK_MECHANISM (CKM_AES_CBC_PAD, iv);
	public static final CK_MECHANISM encMechCtr    = new CK_MECHANISM (CKM_AES_CTR    , iv);
    public static final CK_MECHANISM encMechCbc    = new CK_MECHANISM (CKM_AES_CBC, iv);

    public static final String plainTextInp = "Plain text message to be encrypted.";

	String raw_text;
	long nbrofrows = 0;
	int intnbrofrows = 0;
	String search_type;
	Long biglongnbrofrows = new Long(0);
	

	@Override
	public TransformFunction createTransformFunction(
			ServerInterface srvInterface) {
		return new VormetricEncyrpt();
	}

	@Override
	public void getReturnType(ServerInterface srvInterface,
			SizedColumnTypes input_types, SizedColumnTypes output_types) {
		for (int i = 1; i < input_types.getColumnCount(); i++) {
			StringBuilder cname = new StringBuilder();
			cname.append("col").append(i);
			output_types.addArg(input_types.getColumnType(i), cname.toString());
		}
	}

	@Override
	public void getPrototype(ServerInterface srvInterface,
			ColumnTypes argTypes, ColumnTypes returnType) {
		argTypes.addVarchar();
		// field value from table to encrypt
		argTypes.addVarchar();
		// type of operation to use
		returnType.addVarchar();
	//	results
	}

	public class VormetricEncyrpt extends TransformFunction {

		  String pin = null;
	        String libPath = null;
	        String operation = "CBC_PAD";
	        String charSetStr = null;
	        String charSetInputFile = null;
	        String keyName = "vpkcs11_java_test_key";

	        byte[] tweak = {0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00};
	        CK_MECHANISM encMechFpe = null;
	        CK_MECHANISM encMech = null;
	        
	        Vpkcs11Session session = Helper.startUp(Helper.getPKCS11LibPath(libPath), pin);
	         long keyID = Helper.findKey(session, keyName);

	         
		public void setup(ServerInterface srvInterface,
				SizedColumnTypes argTypes) {

			BlockReader input_reader = srvInterface.getParamReader();
			
			  System.out.println("Start EncryptDecryptMessage ...");
			  int i;

	   
	            if (keyID == 0) {
	                System.out.println("the key is not found, creating it...");
	                keyID = Helper.createKey(session, keyName);
	                System.out.println("Key successfully Created. Key Handle: " + keyID);
	            } else {
	                System.out.println("Key successfully Found. Key Handle: " + keyID);
	            }

	            String plainText, decryptedText;
	            
			long cnt = 0;
			try {
				do {
					 raw_text = input_reader.getString(0);
					 operation = input_reader.getString(1);

			//		boolean valid_nbr = true;
		            byte[] plainBytes;
		            int plainBytesLen;
			// vormetric
		            
		            if (operation.equals("CTR")) {
		                System.out.println("CTR mode selected");
		                encMech = encMechCtr;

		            } else if (operation.equals("FPE")) {
		                System.out.println("FPE mode selected");

		                if(raw_text != null && !raw_text.isEmpty())
		                {
		                    byte[] sortedContent;
		                  //  byte[] byteContent = Files.readAllBytes(Paths.get(charSetInputFile));
		                    byte[] byteContent = raw_text.getBytes();
		                    Arrays.sort(byteContent);
		                    int cnt_len = byteContent.length;

		                    if(cnt_len < 2)
		                    {
		                        sortedContent = byteContent;
		                    }
		                    else {
		                        int j = 0;
		                        i = 1;

		                        while (i < cnt_len) {
		                            if (byteContent[i] == byteContent[j]) {
		                                i++;
		                            } else {
		                                byteContent[++j] = byteContent[i];
		                                i++;
		                            }
		                        }
		                        sortedContent = Arrays.copyOf(byteContent, j + 1);
		                    }

		                    String content = new String(sortedContent, StandardCharsets.UTF_8);

		                    charSetStr = content.replaceAll("[\n\r]", "");
               }

		                byte[] charSet = charSetStr != null ? charSetStr.getBytes() : "0123456789".getBytes();

		                ByteArrayOutputStream fpeIVBytes = new ByteArrayOutputStream(9 + charSet.length);
		                DataOutputStream dos = new DataOutputStream(fpeIVBytes);


		                encMechFpe = new CK_MECHANISM(0x80004001L, fpeIVBytes.toByteArray());

		                encMech = encMechFpe;
		            } else if (operation.equals("CBC")) {
		                System.out.println("CBC mode selected");
		                encMech = encMechCbc;
		            } else {
		                System.out.println("CBC PAD mode selected");
		                encMech = encMechCbcPad;
		            }

		            /* encrypt, decrypt with key */
		            if (raw_text != null) {
		             //   File inputFile = new File(plainInputFile);

		                if (operation.equals("FPE")) {
		                    int skippedLine = 0;
		                    int unmatchedLine = 0;

		                    try {

		                    //    BufferedReader br = new BufferedReader(new FileReader(plainInputFile));
		                        String line = raw_text;
		                       // while ((line = br.readLine()) != null) {
		                            plainText = line.replaceAll("[\n\r]", "");
		                            if(plainText.length() >= 2) {
		                                plainBytes = plainText.getBytes();
		                                decryptedText = encryptDecryptBuf(session, encMech, keyID, plainBytes);

		                                if (plainText.equals(decryptedText)) {
		                                    System.out.println("=== plainText and decryptedTextStr are equal ===");
		                                } else {
		                                    unmatchedLine++;
		                                    System.out.println("=== plainText and decryptedTextStr are NOT equal ===");
		                                }
		                                Thread.sleep(2000);


		                            }
		                            else {
		                                System.out.println("Fpe mode only supports input length >= 2.");
		                                skippedLine++;
		                                continue;
		                            }
		                    //    }
		                        System.out.println("Skipped Line Count: "+skippedLine);
		                        System.out.println("Unmatched Line Count: "+unmatchedLine);

		                    } catch (Exception ex) {
		                        ex.printStackTrace();
		                    }
		                }
		                else {
		                 int bytesLen = raw_text.length();
		                    plainBytes = new byte[bytesLen];

		                    plainText = new String(plainBytes);

		                    decryptedText = encryptDecryptBuf(session, encMech, keyID, plainBytes);

		                }
		            } else {
		                plainBytes = plainTextInp.getBytes();
		                decryptedText = encryptDecryptBuf(session, encMech, keyID, plainBytes);

		            }

		            
		            //vormetric

					// output_writer.setLong(0,nbrofrows);

					// output_writer.next();

				} while (input_reader.next());

			} catch (UdfException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (DestroyInvocation e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

		}

		public void destroy(ServerInterface srvInterface,
				SizedColumnTypes argTypes) {
		//	client.close();
		    Helper.closeDown(session);
            System.out.println("End EncryptDecryptMessage.");
		}

		@Override
		public void processPartition(ServerInterface srvInterface,
				PartitionReader input_reader, PartitionWriter output_writer)
				throws UdfException, DestroyInvocation {

			output_writer.setString(0, biglongnbrofrows.toString());
			//output_writer.setString(1, search_type);
			
			//bigIntNumberRows = new Integer(nbrofrows);
			
			//output_writer.setLong(0, nbrofrows);
			
		 

		}
		
        public  String  encryptDecryptBuf(Vpkcs11Session session, CK_MECHANISM encMech, long keyID, byte[] plainBytes)
        {
            try {
                byte[] encryptedText;
                byte[] decryptedText;
                int encryptedDataLen = 0;
                int decryptedDataLen = 0;
                byte[] outText = {};

                int plainBytesLen = plainBytes.length;
                System.out.println("plaintext byte length: " + plainBytesLen);

                session.p11.C_EncryptInit(session.sessionHandle, encMech, keyID);
                System.out.println("C_EncryptInit success.");

                encryptedDataLen = session.p11.C_Encrypt(session.sessionHandle, plainBytes, 0, plainBytesLen, outText, 0, 0);
                System.out.println("C_Encrypt success. Encrypted data len = " + encryptedDataLen);

                encryptedText = new byte[encryptedDataLen];
                session.p11.C_Encrypt(session.sessionHandle, plainBytes, 0, plainBytesLen, encryptedText, 0, encryptedDataLen);
                System.out.println("C_Encrypt 2nd call succeed. Encrypted data len = " + encryptedDataLen);

                System.out.println("Encrypted Text =  " + new String(encryptedText, 0, encryptedDataLen));
               // encryptedOutFS.write(encryptedText, 0, encryptedDataLen);


                session.p11.C_DecryptInit(session.sessionHandle, encMech, keyID);
                System.out.println("C_DecryptInit success.");

                decryptedDataLen = session.p11.C_Decrypt(session.sessionHandle, encryptedText, 0, encryptedText.length, outText, 0, 0);
                System.out.println("C_Decrypt success. Decrypted data length = " + decryptedDataLen);

                decryptedText = new byte[decryptedDataLen];
                decryptedDataLen = session.p11.C_Decrypt(session.sessionHandle, encryptedText, 0, encryptedText.length, decryptedText, 0, decryptedDataLen);
                System.out.println("C_Decrypt 2nd call succeed. Decrypted data length = " + decryptedDataLen);

                String decryptedTextStr = new String(decryptedText, 0, decryptedDataLen);
                String plainTextStr = new String(plainBytes);

                System.out.println("Plaintext = " + plainTextStr);
                System.out.println("Decrypted Text = " + decryptedTextStr);

                return decryptedTextStr;

            } catch (PKCS11Exception e) {
                e.printStackTrace();
            } catch (Exception ex) {
                ex.printStackTrace();
            }
            return null;
        }
        

	}
}

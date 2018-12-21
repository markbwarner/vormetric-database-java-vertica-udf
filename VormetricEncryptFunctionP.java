/* Copyright (c) 2005 - 2014, Hewlett-Packard Development Co., L.P.  -*- Java -*-*/
/* 
 *
 * Description: Example User Defined Scalar Function: Add 2 ints
 *
 * Create Date: June 1, 2013
 */

package com.vertica.JavaLibs;

import com.vertica.sdk.*;
import java.io.*;


import java.net.*;


public class VormetricEncryptFunctionP extends ScalarFunctionFactory {



	public static final String plainTextInp = "Plain text message to be encrypted.";

	static String  application = "hr";
	String inputdata = "app:machine:operation:value";
	
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

	public class VormetricEncryptDataP extends ScalarFunction {
		// note took out override...

		String raw_text;

		Socket s;
		DataOutputStream os = null;
		DataInputStream is = null;
		BufferedReader in = null;
		
		public void setup(ServerInterface srvInterface, SizedColumnTypes argTypes) {

		
			try {
				s = new Socket( "192.168.159.134",8181);


			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}



		}

		public void destroy(ServerInterface srvInterface, SizedColumnTypes argTypes) {
			
			try {


				s.close();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

			srvInterface.log("End EncryptDecryptMessage.");

		}

		public void processBlock(ServerInterface srvInterface, BlockReader arg_reader, BlockWriter res_writer)
				throws UdfException, DestroyInvocation {

			do {
				String raw_text = arg_reader.getString(0);

				String operation = arg_reader.getString(1);

				if (operation.equalsIgnoreCase("CBC") || operation.equalsIgnoreCase("CBC_PAD")
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
				

				boolean valid_nbr = true;

				srvInterface.log("Start EncryptDecryptMessage ...raw_text " + raw_text + " oper " +operation );


				if (valid_nbr) {

					if (operation.equals("CTR")) {
						srvInterface.log("CTR mode selected");
					

					} else if (operation.equals("FPE")) {
						srvInterface.log("FPE mode selected");



					} else if (operation.equals("CBC")) {
						srvInterface.log("CBC mode selected");
		
						srvInterface.log("CBC PAD mode selected");
					
					}

					/* encrypt, decrypt with key */

					//plainBytes = raw_text.getBytes();

				  // will want to send raw_text
				//	if (s != null ) {	
					try {
						os = new DataOutputStream(s.getOutputStream());
						is = new DataInputStream(s.getInputStream());			
 	if (s != null && os != null && is != null) {
						
				//	if (s != null) {
						// "5471949763376677", "5545127221796024",
						// The capital string before each colon has a special meaning to
						// SMTP
						// you may want to read the SMTP specification, RFC1822/3
						StringBuffer sb = new StringBuffer();
						sb.append(application);
						sb.append(":");

						String hostname;
						
							hostname = getHostName();
							sb.append(hostname);
							sb.append(":");
							sb.append("CBC_PAD");
							sb.append(":");
							sb.append(raw_text);
							sb.append(" \n");
						//	sb.append("5471949763376677 \n");
							os.writeBytes(sb.toString());
							
							//OutputStream out = s.getOutputStream();


							
							 in = new BufferedReader(new InputStreamReader(s.getInputStream()));
							String responseLine = null;
	 						responseLine = is.readLine();
	 							srvInterface.log("Server: " + responseLine);
								
/*							while ((responseLine = is.readLine()) != null) {
								srvInterface.log("Server: " + responseLine);
								if (responseLine.indexOf("stop") != -1) {
									break;
								}
							}*/
							
							
							res_writer.setString(responseLine);
							
//							in.close();
//							os.close();
//							is.close();
							
					}

						} catch (UnknownHostException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						} catch (IOException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					
					}
					//decryptedText = encryptDecryptBuf(session, encMech, keyID, plainBytes, srvInterface);
	

				
		

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


	@Override
	public ScalarFunction createScalarFunction(ServerInterface srvInterface) {
		return new VormetricEncryptDataP();
	}
	


	
	public static String getHostName() throws UnknownHostException
	{
	       InetAddress iAddress = InetAddress.getLocalHost();
	        String hostName = iAddress.getHostName();
	        //To get  the Canonical host name
	        String canonicalHostName = iAddress.getCanonicalHostName();

	        System.out.println("HostName:" + hostName);
	        System.out.println("Canonical Host Name:" + canonicalHostName);
	        return canonicalHostName;
		
		
	}

}

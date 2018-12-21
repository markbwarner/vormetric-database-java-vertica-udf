package com.vertica.JavaLibs;
/* Sample Vertica/Vormetric User Defined Function.
  Tested with Vormetric DSM 6.0.3 
  VTS Version 2.2
  Vertica Version 8.0.1
 */

import com.jayway.jsonpath.JsonPath;
import com.vertica.sdk.*;

import javax.net.ssl.HttpsURLConnection;

import org.apache.commons.codec.binary.Base64;

import java.io.*;
import java.net.MalformedURLException;
import java.net.URL;

public class VormetricEncryptVTS extends ScalarFunctionFactory {

	String trustedstoredefaultlocation = "/tmp/mytrustedvtskeystore";
	String vtshostip = "192.168.159.141";
	String user = "vtsroot";
	String alg = "A128CTR";
	String ivnumber = "0123456789012345";
	String ivtext = "Thisisatestonlya";
	String commmntag = "VTS";

	public static final String plainTextInp = "Plain text message to be encrypted.";

	@Override
	public void getPrototype(ServerInterface srvInterface, ColumnTypes argTypes, ColumnTypes returnType) {
		// field name is column to encrypt
		argTypes.addVarchar();
		// argTypes.addVarchar();
		// field name operation
		returnType.addVarchar();

	}

	public class VormetricEncryptVTSData extends ScalarFunction {

		public void setup(ServerInterface srvInterface, SizedColumnTypes argTypes) {

			srvInterface.log(commmntag + " In setup");
			System.setProperty("javax.net.ssl.trustStore", trustedstoredefaultlocation);

			javax.net.ssl.HttpsURLConnection.setDefaultHostnameVerifier(new javax.net.ssl.HostnameVerifier() {

				public boolean verify(String hostname, javax.net.ssl.SSLSession sslSession) {

					return hostname.equals(vtshostip);
				}
			});
			srvInterface.log(commmntag + " After  setup");
		}

		public void destroy(ServerInterface srvInterface, SizedColumnTypes argTypes) {

			srvInterface.log(commmntag + " End EncryptDecryptMessage.");

		}

		public void processBlock(ServerInterface srvInterface, BlockReader arg_reader, BlockWriter res_writer)
				throws UdfException, DestroyInvocation {

			do {
				srvInterface.log(commmntag + " processBlock begin");
				String userpwd = user + ":Vormetric123!";
				String credential = Base64.encodeBase64String(userpwd.getBytes());
				String inputdata = Base64.encodeBase64String(arg_reader.getString(0).getBytes());
				String encdata = "";
				int respcode = 0;

				String strResponse = "";
				// https://{{vtshost}}/vts/crypto/v1/encrypt
				String https_url = "https://" + vtshostip + "/vts/crypto/v1/encrypt";
				URL myurl;

				srvInterface.log(commmntag + " process block before inputdata " + inputdata);
		 	try {
					myurl = new URL(https_url);
					HttpsURLConnection con = (HttpsURLConnection) myurl.openConnection();
					srvInterface.log(commmntag + " URL " + con.getURL());
					// {"plaintext" : "VGhpc2lzYXRlc3R0aGlzaXNvbmx5YXRlc3Q="
					// ,"alg" : "A128CTR", "params" : {"iv":
					// "MTIzNDU2Nzg5MDEyMzQ1Ng=="}, "kid": "firstkeyviarest128"}
					// {"plaintext":"MTc3MjQ3OA==","alg":"A128CTR,"params"
					// :{"iv":"MDEyMzQ1Njc4OTAxMjM0NQ==},"kid":
					// "firstkeyviarest128"}
					String jStr = "{\"plaintext\":\"" + inputdata + "\",\"alg\":\"" + alg + "\",\"params\" : {\"iv\":\""
							+ Base64.encodeBase64String(ivnumber.getBytes()) + "\"},\"kid\": \"firstkeyviarest128\"}";
					srvInterface.log(commmntag + " payload " + jStr);
					// String jStr = "{\"data\":\"" + ccNum +
					// "\",\"tokengroup\":\"t1\",\"tokentemplate\":\"Credit
					// Card\"}";
					con.setRequestProperty("Content-length", String.valueOf(jStr.length()));
					con.setRequestProperty("Content-Type", "application/json");
					con.setRequestProperty("Authorization", "Basic " + credential);
					con.setRequestMethod("POST");
					con.setDoOutput(true);
					con.setDoInput(true);

					respcode = con.getResponseCode();
					srvInterface.log(commmntag + "  respcode   : " + respcode);
					String respmsg = con.getResponseMessage();
					srvInterface.log(commmntag + " respmsg   : " + respmsg);

				//	if (respcode == 200) {

						DataOutputStream output = new DataOutputStream(con.getOutputStream());
						output.writeBytes(jStr);
						output.close();
						BufferedReader rd = new BufferedReader(new InputStreamReader(con.getInputStream()));
						String line = "";

						while ((line = rd.readLine()) != null) {
							strResponse = strResponse + line;
						}
						rd.close();
						
						encdata = JsonPath.read(strResponse, "$.ciphertext").toString();

			//		}
				/*	else
					{
						srvInterface.log(commmntag + "  respcode   : " + respcode);
						srvInterface.log(commmntag + " respmsg   : " + respmsg);
					}*/

					
					con.disconnect();

		 		} catch (MalformedURLException e) {
					// TODO Auto-generated catch block
		 			e.printStackTrace();
		 		} catch (IOException e) {
					// TODO Auto-generated catch block
		 		e.printStackTrace();
	 			}

			//	if (respcode != 200) {
					// if (JsonPath.read(strResponse,
					// "$.status").toString().equals("error")) {
				//	srvInterface.log(commmntag + " Error here is the return: " + strResponse);

			//	} else {
		//			encdata = JsonPath.read(strResponse, "$.ciphertext").toString();

			//		srvInterface.log(commmntag + " Encrypted data  : " + encdata);
			//		srvInterface.log(commmntag + " Encrypted data response: " + strResponse);
			//	}

				res_writer.setString(encdata);

				res_writer.next();

			} while (arg_reader.next());

		}

	}

	@Override
	public void getReturnType(ServerInterface srvInterface, SizedColumnTypes argTypes, SizedColumnTypes returnType) {
		returnType.addVarchar((argTypes.getColumnType(0).getStringLength() + 200) * 2, argTypes.getColumnName(0));
	}

	@Override
	public ScalarFunction createScalarFunction(ServerInterface srvInterface) {
		return new VormetricEncryptVTSData();
	}

}

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


public class VormetricEncryptToken extends ScalarFunctionFactory {

	String trustedstoredefaultlocation = "/tmp/mytrustedvtskeystore";
	String vtshostip = "192.168.159.141";
	String user = "vtsroot";

	public static final String plainTextInp = "Plain text message to be encrypted.";


	@Override
	public void getPrototype(ServerInterface srvInterface, ColumnTypes argTypes, ColumnTypes returnType) {
		// field name is column to encrypt
		argTypes.addVarchar();
	//	argTypes.addVarchar();
		// field name operation
		returnType.addVarchar();

	}

	public class VormetricTokenizeData extends ScalarFunction {

		public void setup(ServerInterface srvInterface, SizedColumnTypes argTypes) {

			srvInterface.log("In setup");
			System.setProperty("javax.net.ssl.trustStore", trustedstoredefaultlocation);
			
			javax.net.ssl.HttpsURLConnection.setDefaultHostnameVerifier(new javax.net.ssl.HostnameVerifier() {

				public boolean verify(String hostname, javax.net.ssl.SSLSession sslSession) {
					
					return hostname.equals(vtshostip);
				}
			}); 
			srvInterface.log("After  setup");
		}

		public void destroy(ServerInterface srvInterface, SizedColumnTypes argTypes) {
	
			srvInterface.log("End EncryptDecryptMessage.");

		}

		public void processBlock(ServerInterface srvInterface, BlockReader arg_reader, BlockWriter res_writer)
				throws UdfException, DestroyInvocation {

			do {
				srvInterface.log("processBlock begin");
				String userpwd = user+ ":Vormetric123!";
				String credential = Base64.encodeBase64String(userpwd.getBytes());
				String ccNum = arg_reader.getString(0);
				String token = "";
			
				

				String strResponse = "";
				String https_url = "https://" + vtshostip + "/vts/rest/v2.0/tokenize/";
				URL myurl;
				
				srvInterface.log("process block before try ");
				try {
					myurl = new URL(https_url);
					HttpsURLConnection con = (HttpsURLConnection) myurl.openConnection();

					String jStr = "{\"data\":\"" + ccNum + "\",\"tokengroup\":\"t1\",\"tokentemplate\":\"Credit Card\"}";
					con.setRequestProperty("Content-length", String.valueOf(jStr.length()));
					con.setRequestProperty("Content-Type", "application/json");
					con.setRequestProperty("Authorization", "Basic " + credential);
					con.setRequestMethod("POST");
					con.setDoOutput(true);
					con.setDoInput(true);

					DataOutputStream output = new DataOutputStream(con.getOutputStream());
					output.writeBytes(jStr);
					output.close();
					BufferedReader rd = new BufferedReader(new InputStreamReader(con.getInputStream()));
					String line = "";

					while ((line = rd.readLine()) != null) {
						strResponse = strResponse + line;
					}
					rd.close();
					con.disconnect();

				} catch (MalformedURLException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				
				
				
			
				if (JsonPath.read(strResponse, "$.status").toString().equals("error")) {
					srvInterface.log("Error here is the return: " + strResponse);

				} else {
					 token = JsonPath.read(strResponse, "$.token").toString();
					
				
					 srvInterface.log("Token : " + token);
					 srvInterface.log("Tokenize response: " + strResponse);
				}
				

				res_writer.setString(token);

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
		return new VormetricTokenizeData();
	}
	
}


/*
 * Handles interation with Censys
 *
 * Chris McMahon-Stone (c.mcmahon-stone@cs.bham.ac.uk)
 */

import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.net.InetSocketAddress;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.http.HttpResponse;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

public class CheckCertificate {
	static int portNo = 443;
	static boolean verbose = false;

	/**
	 * Gets the certificates used by the server and prints Issuer details to
	 * STDOUT
	 * 
	 * @param host
	 *            Hostname to download certificates for
	 * @return Issuer details of each certificates concatentated together.
	 */
	public static Cert[] getCertificates(String host) {

		try {
			TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {
				public java.security.cert.X509Certificate[] getAcceptedIssuers() {
					return null;
				}

				public void checkClientTrusted(X509Certificate[] certs, String authType) {
				}

				public void checkServerTrusted(X509Certificate[] certs, String authType) {
				}
			} };

			// Install the all-trusting trust manager
			SSLContext sc = SSLContext.getInstance("TLSv1.2");
			sc.init(null, trustAllCerts, new java.security.SecureRandom());

			// Open TLS connection with host
			SSLSocket socket = (SSLSocket) sc.getSocketFactory().createSocket();
			socket.connect(new InetSocketAddress(host, portNo), 10000);
			// Start TLS handshake
			socket.startHandshake();
			// Get session certificates
			javax.security.cert.X509Certificate[] certs = socket.getSession().getPeerCertificateChain();
			// Print number of certificates provided by host
			StringBuilder result = new StringBuilder();
			Cert[] cs = new Cert[certs.length];
			for (int i = 0; i < certs.length; i++) {
				String dn = certs[i].getSubjectDN().getName();
				LdapName ln = new LdapName(dn);
				for (Rdn rdn : ln.getRdns()) {
					if (rdn.getType().equalsIgnoreCase("CN")) {
						cs[i] = new Cert(certs[i].getEncoded(), rdn.getValue().toString());
						break;
					}
				}
			}
			return cs;
		} catch (Exception e) {
			System.out.println("Get certificate failed for host: " + host);
			return null;
		}
	}

	/**
	 * @param host
	 *            hostname to check certificate
	 * @param mapFile
	 *            the file path of a HashMap<String, ArrayList<String>> file.
	 * @return a random host that use the same TLS certificate as the given host
	 */
	@SuppressWarnings("unchecked")
	public static String censysLookup(String urlRequested, String certCN, String ID, String secret) {

		ArrayList<String> alternateHosts = new ArrayList<>();
		SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

		try {
			CloseableHttpClient httpclient = HttpClients.createDefault();
			HttpPost post = new HttpPost("https://www.censys.io/api/v1/search/certificates");
			post.setHeader("User-Agent", "python-requests/2.13.0");
			String base64 = Base64.getEncoder().encodeToString((ID + ":" + secret).getBytes("utf-8"));
			post.setHeader("Authorization", "Basic " + base64);
			String jsonQuery = "{" + "  \"query\":\"443.https.tls.certificate.parsed.issuer.common_name: " + certCN
					+ "\"," + "  \"page\":1,"
					+ "  \"fields\":[\"parsed.subject.common_name\", \"parsed.validity.end\"]," + "  \"flatten\":false"
					+ "}";
			StringEntity requestEntity = new StringEntity(jsonQuery, ContentType.APPLICATION_JSON);
			post.setEntity(requestEntity);
			HttpResponse response = httpclient.execute(post);
			JsonObject json = new JsonParser().parse(EntityUtils.toString(response.getEntity())).getAsJsonObject();
			if (json.get("status").getAsString().equals("ok")) {
				JsonArray results = json.getAsJsonArray("results");
				for (int i = 0; i < results.size(); i++) {
					try {
						String validity = results.get(i).getAsJsonObject().get("parsed").getAsJsonObject()
								.get("validity").getAsJsonObject().get("end").getAsString().replaceAll("Z", "")
								.replaceAll("T", " ");
						if (sdf.parse(validity).before(new Date()))
							continue;
						String cn = results.get(i).getAsJsonObject().get("parsed").getAsJsonObject().get("subject")
								.getAsJsonObject().get("common_name").getAsJsonArray().get(0).getAsString();
						if (cn != null && !cn.contains(urlRequested) && !cn.contains("*."))
							alternateHosts.add(cn);
					} catch (Exception e) {
						continue;
					}
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
		if (alternateHosts.size() > 1) {
			return alternateHosts.get(new Random().nextInt(alternateHosts.size()));
		} else {
			return null;
		}
	}
}

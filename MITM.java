/**
 * Man in the middle server that listens for connections on port 443.
 * Forwards traffic to a specified host and, decodes stages of 
 * TLS handshake and prints to STDOUT.
 * Any fatal handshake alerts will close the connection.
 *
 * Chris McMahon-Stone (c.mcmahon-stone@cs.bham.ac.uk)
 */

import java.net.*;
import java.io.*;
import java.util.*;

public class MITM implements Runnable {

    //Listening on port no
    private int clientPortNo = 443;
    //Forward traffic to host on port
    private int serverPortNo = 443;
    //Forwarding host
    private Map<String, String> redirectHosts;
    //verbose = 0: print nothing
    //verbose = 1: print forwarding details
    //verbose = 2: print handshake details
    private int verbose;
    private long connectionTimeout = 5000;
    private PrintWriter outLog;
    private Map<String, byte[]> realLeafCerts;
    private Map<String, byte[]> realIssuerCerts;
    private volatile boolean connectionWaiting = true;
    private boolean manual = false;
    private volatile String forwardingHost;
    private volatile String realHost;
    private boolean passthrough;
    private Map<String, String> cachedAlternateHosts;

	public MITM(int verbose, PrintWriter outLog, boolean manual, boolean passthrough) {
        this.verbose = verbose;
        this.outLog = outLog;
        this.manual = manual;
        this.redirectHosts = (new HashMap<String, String>());
        this.realIssuerCerts = (new HashMap<String, byte[]>());
        this.realLeafCerts = (new HashMap<String, byte[]>());
        this.cachedAlternateHosts = (new HashMap<>());
        this.passthrough = passthrough;
    }

    public void run() {
        Thread sessionThread = null;
        ServerSocket listener = null;
        try {
            //Listen for connections
            listener = new ServerSocket(clientPortNo);
            listener.setSoTimeout(500);
            if(verbose > 0) System.out.println("# Listening on TCP port 443");

            while(true) {
                if(Thread.currentThread().isInterrupted()) throw new InterruptedException();
                Socket connection;
                try { connection = listener.accept();} catch (SocketTimeoutException e) {continue;}
                connectionWaiting = false;
                if(verbose > 0) System.out.println("# Connection with client made");
                outLog.println("# Connection with client made");
                if((forwardingHost == null || forwardingHost.isEmpty()) && !passthrough) {
                    if(verbose > 0) System.out.println("WARNING: No redirect host set, dropping connection. Ensure DNS requests are directed to Spinner, or set redirect host manually with -m flag.");
                    outLog.println("WARNING: No redirect host set, dropping connection. Ensure DNS requests are directed to Spinner, or set redirect host manually with -m flag.");
                    connectionWaiting = true;
                    continue;
                }
                //Spin off new thread & continue listening
                sessionThread = new Thread(new SSLSession(connection, realHost, forwardingHost));
                sessionThread.start();
                sessionThread.join();
                connectionWaiting = true;
            }
            //Deal with exceptions
        } catch(InterruptedException e) {
            if(sessionThread != null) sessionThread.interrupt();
        } catch (IOException e) {
            System.out.println(e.getMessage());
            outLog.println(e.getMessage());
        } finally {
            try {
                if(listener != null) listener.close();
            } catch (IOException e2) {
                System.out.println(e2.getMessage());
                outLog.println(e2.getMessage());
            }
            connectionWaiting = true;
        }
    }
    
	public String getForwardingHost() {
			return forwardingHost;
	}

	public void setForwardingHost(String forwardingHost) {
		this.forwardingHost = forwardingHost;
	}
    /**
     * Returns whether the 
     */
    public boolean isConnectionWaiting() {
        return connectionWaiting;
    }

	public Map<String, String> getRedirectHosts() {
		return redirectHosts;
	}

	public void addRedirectHost(String from, String to) {
		this.redirectHosts.put(from, to);
	}

	public Map<String, byte[]> getRealLeafCerts() {
		return realLeafCerts;
	}

	public void addRealLeafCert(String host, byte[] leafCert) {
		this.realLeafCerts.put(host, leafCert);
	}

	public Map<String, byte[]> getRealIssuerCerts() {
		return realIssuerCerts;
	}

	public void addRealIssuerCert(String host, byte[] issuerCert) {
		this.realIssuerCerts.put(host, issuerCert);
	}

	public String getRealHost() {
		return realHost;
	}

	public void setRealHost(String realHost) {
		this.realHost = realHost;
	}

	public Map<String, String> getCachedAlternateHosts() {
		return cachedAlternateHosts;
	}

	public void addCachedAlternateHost(String urlRequested, String alternateHost) {
		this.cachedAlternateHosts.put(urlRequested, alternateHost);
	}

	/**
     * Handles the SSLSession between a client and server, forwarding
     * data between each and printing details to STDOUT.
     */
    private class SSLSession implements Runnable {

        Socket clientConnection;
        Socket serverConnection;
        //Map storing alert hex values to messages
        Map<Integer, String> alertMap;
        //Map storing handshake hex values to messages
        Map<Integer, String> handShakeMap;
        OutputStream clientOutStream;
        InputStream clientInStream;
        OutputStream serverOutStream;
        InputStream serverInStream;
        String forwardHost;
        String realHost;

        public SSLSession(Socket clientConnection, String realHost, String host) {
            this.clientConnection = clientConnection;
            this.forwardHost = host;
            this.realHost = realHost;
            alertMap = new HashMap<Integer, String>();
            handShakeMap = new HashMap<Integer, String>();
            fillMaps();
        }

        public void run() {

            try {
                //Get I/O streams for client 
                clientOutStream = clientConnection.getOutputStream();
                clientInStream = clientConnection.getInputStream();

                if(verbose > 1) System.out.println("    STARTED HANDSHAKE");
                outLog.println("    STARTED HANDSHAKE");
                //Some flags
                boolean clientAlert = false;
                boolean serverAlert = false;
                boolean handShake = false;
                boolean failed = false;
                boolean finished = false;
                boolean serverCCS = false;
                boolean clientCCS = false;
                boolean timeout = false;
                int messageCount = 0;
                long timeoutExpiredMs = System.currentTimeMillis() + connectionTimeout;

                while(true) {
                    if(Thread.currentThread().isInterrupted()) { throw new InterruptedException(); }
                    //Check if client has sent any data
                    while(clientInStream.available() > 0) {

                        if(!Thread.currentThread().isInterrupted()) {
                            messageCount++;

                            //Read in TLS record header
                            byte[] header = new byte[5];
                            clientInStream.read(header);

                            //Decode record type
                            switch(header[0]) {
                                case 22:
                                    if(clientCCS) {
                                        if(verbose > 1) System.out.println("    " + messageCount + ". Encrypted client Handshake message");
                                        outLog.println("    " + messageCount + ". Encrypted client Handshake message");
                                    } else {
                                        if(verbose > 1) System.out.print("    " + messageCount + ". Client Handshake message: ");
                                        outLog.print("    " + messageCount + ". Client Handshake message: ");
                                    }
                                    handShake = true;
                                    break;
                                case 23:
                                    if(verbose > 1) System.out.println("    " + messageCount + ". Sending application data to server");
                                    outLog.println("    " + messageCount + ". Sending application data to server");
                                    finished = true;
                                    break;
                                case 20:
                                    if(verbose > 1) System.out.println("    " + messageCount + ". Client ChangeCipherSpec");
                                    outLog.println("    " + messageCount + ". Client ChangeCipherSpec");
                                    clientCCS = true;
                                    break;
                                case 21:
                                    if(clientCCS) {
                                        if(verbose > 1) System.out.println("    " + messageCount + ". Client sent an encrypted Alert message");
                                        outLog.println("    " + messageCount + ". Client sent an encrypted Alert message");
                                        failed = true;
                                    } else {
                                        if(verbose > 1) System.out.print("    " + messageCount + ". Client sent an Alert: ");
                                        outLog.print("    " + messageCount + ". Client sent an Alert: ");
                                        clientAlert = true;
                                    }
                                    break;
                                default:
                                    if(verbose > 1) System.out.println("    " + messageCount + ". Unknown message from client");
                                    outLog.println("    " + messageCount + ". Unknown message from client");
                            }

                            //Caculate length of message excluding header
                            int length = ((header[3] & 0xff) << 8) | (header[4] & 0xff);
                            byte[] data = new byte[length];

                            //Read in rest of TLS message
                            for(int i=0; i<length; i++) {
                                data[i]=(byte) (clientInStream.read() & 0xff);
                            }

                            //Deal with Alerts
                            if(!clientCCS) {
                                if(clientAlert && data[0] == 1) {
                                    if(verbose > 1) System.out.print("Fatal ");
                                    outLog.print("Fatal ");
                                    if(verbose > 1) System.out.println(alertMap.get((int)data[1]));
                                    outLog.println(alertMap.get((int)data[1]));
                                    failed = true;
                                } else if (clientAlert) {
                                    if(verbose > 1) System.out.print("Warning ");
                                    outLog.print("Warning ");
                                    if(verbose > 1) System.out.println(alertMap.get((int)data[1]));
                                    outLog.println(alertMap.get((int)data[1]));
                                }
                            }

                            //Combine header with rest of message
                            byte[] forwardMessage = new byte[5 + length];
                            System.arraycopy(header, 0, forwardMessage, 0, header.length);
                            System.arraycopy(data, 0, forwardMessage, header.length, data.length);

                            //Print handshake message
                            if(!clientCCS && handShake) {
                                String messageString = handShakeMap.get((int)forwardMessage[5]);
                                if(messageString == null) messageString = "UNKNOWN_MESSAGE_TYPE";

                                //Log handshake type
                                if(verbose > 1) System.out.println(messageString);
                                outLog.println(messageString);
                                
                                if(messageString.equals("CLIENT_HELLO")) {
                                	String sni = extractSNI(data);
                                	if(sni != null) {
										System.out.println("      > SNI: " + sni);
										outLog.println("      > SNI: " + sni);
                                		setForwardHost(redirectHosts.get(sni));
                                		setRealHost(sni);
                                	} else {
										System.out.println("      > No SNI, using last DNS lookup");
										outLog.println("      > No SNI, using last DNS lookup");
                                	}
                                	if(passthrough) this.forwardHost = sni;
									System.out.println("      > Forwarding to: " + this.forwardHost);
									outLog.println("      > Forwarding to: " + this.forwardHost);
									this.serverConnection = new Socket();
									try {
										serverConnection.connect(new InetSocketAddress(this.forwardHost, 443), 10000);
									} catch (Exception e) {
										System.out.println("      > ERROR: Failed to connect to selected redirect host. Restart Spinner to try with different host.");
										cachedAlternateHosts.remove(this.realHost);
										return;
										
									}
									serverOutStream = serverConnection.getOutputStream();
									serverInStream = serverConnection.getInputStream();
                                }
                            }
                            

                            //Forward TLS message to server
                            serverOutStream.write(forwardMessage);
                            clientAlert = false;
                            handShake = false;
                        } else { 
                            break;
                        }

                    }

                    //Check if server has sent any data
                    while(serverInStream != null && serverInStream.available() > 0) {

                        if(!Thread.currentThread().isInterrupted()) {
                            messageCount++;

                            //Read in TLS record header
                            byte[] header = new byte[5];
                            serverInStream.read(header);

                            //Decode record type
                            switch(header[0]) {
                                case 22:
                                    if(serverCCS) {
                                        if(verbose > 1) System.out.println("    " + messageCount + ". Encrypted server Handshake message");
                                        outLog.println("    " + messageCount + ". Encrypted server Handshake message");
                                    } else {
                                        if(verbose > 1) System.out.print("    " + messageCount + ". Server Handshake message: ");
                                        outLog.print("    " + messageCount + ". Server Handshake message: ");
                                    }
                                    handShake = true;
                                    break;
                                case 23:
                                    if(verbose > 1) System.out.println("    " + messageCount + ". Sending application data to client");
                                    outLog.println("    " + messageCount + ". Sending application data to client");
                                    break;
                                case 20:
                                    if(verbose > 1) System.out.println("    " + messageCount + ". Server ChangeCipherSpec");
                                    outLog.println("    " + messageCount + ". Server ChangeCipherSpec");
                                    serverCCS = true;
                                    break;
                                case 21:
                                    if(serverCCS) {
                                        if(verbose > 1) System.out.println("    " + messageCount + ". Server sent an encrypted Alert message");
                                        outLog.print("    " + messageCount + ". Server sent an encrypted Alert message");
                                    } else {
                                        if(verbose > 1) System.out.print("    " + messageCount + ". Server sent an Alert: ");
                                        outLog.print("    " + messageCount + ". Server sent an Alert: ");
                                    }
                                    serverAlert = true;
                                    break;
                                default:
                                    if(verbose > 1) System.out.println("    " + messageCount + ". Unknown message from client");
                                    outLog.println("    " + messageCount + ". Unknown message from client");
                            }

                            //Caculate length of message excluding header
                            int length = ((header[3] & 0xff) << 8) | (header[4] & 0xff);
                            byte[] data = new byte[length];

                            //Read in rest of TLS message
                            for(int i=0; i<length; i++) {
                                data[i]=(byte) (serverInStream.read() & 0xff);
                            }

                            //Deal with Alerts
                            if(!serverCCS) {
                                if(serverAlert && data[0] == 2) {
                                    if(verbose > 0) System.out.print("Fatal ");
                                    outLog.print("Fatal ");
                                    if(verbose > 0) System.out.println(alertMap.get((int)data[1]));
                                    outLog.println(alertMap.get((int)data[1]));
                                    failed = true;
                                } else if (serverAlert) {
                                    if(verbose > 0) System.out.print("Warning ");
                                    outLog.print("Warning ");
                                    if(verbose > 0) System.out.println(alertMap.get((int)data[1]));
                                    outLog.println(alertMap.get((int)data[1]));
                                }
                            }

                            //Combine header with rest of message
                            byte[] forwardMessage = new byte[5 + length];
                            System.arraycopy(header, 0, forwardMessage, 0, header.length);
                            System.arraycopy(data, 0, forwardMessage, header.length, data.length);

                            //Print handshake message
                            if(!serverCCS && handShake) {
                                String messageString = handShakeMap.get((int)forwardMessage[5]);
                                if(messageString == null) messageString = "UNKNOWN_MESSAGE_TYPE";

                                //Log handshake type
                                if(verbose > 1) System.out.println(messageString);
                                outLog.println(messageString);

                                //Check same certificate is not being served, despite being sent to different address
                                
                                if(messageString.equals("CERTIFICATE")){
                                	int index = 12;
                                    int leafCertLength = ((forwardMessage[index++] & 0xff) << 16) | ((forwardMessage[index++] & 0xff) << 8) | (forwardMessage[index++] & 0xff);
                                    if(leafCertLength == getRealLeafCerts().get(this.realHost).length) {
                                        //Check if message is server certificate
                                        for(int i=0; i<leafCertLength; i++) {
                                            if(forwardMessage[i+index] != getRealLeafCerts().get(this.realHost)[i]) break;
                                            if(i+1 == leafCertLength) {
                                                if(verbose > 1) System.out.println("CERT WARNING: Same certificate as legitimate domain detected, possible SNI in use by hosting providers");
                                                outLog.println("CERT WARNING: Same certificate as legitimate domain detected, possible SNI in use by hosting providers");
                                            }
                                        }
                                    }
									index += leafCertLength;
                                    if(forwardMessage.length > index) {
										int issuerCertLength = ((forwardMessage[index++] & 0xff) << 16) | ((forwardMessage[index++] & 0xff) << 8) | (forwardMessage[index++] & 0xff);
										if(issuerCertLength != getRealIssuerCerts().get(this.realHost).length) {
											//Check if message is server certificate
											for(int i=0; i<issuerCertLength; i++) {
												if(forwardMessage[i+index] != getRealIssuerCerts().get(this.realHost)[i]) {
													if(verbose > 1) System.out.println("CERT WARNING: Chosen redirect domain has different issuer cert.");
													outLog.println("CERT WARNING: Chosen redirect domain has different issuer cert.");
													break;
												}
											}
										} 
                                    }
                                }
                            }
                            clientOutStream.write(forwardMessage);
                            serverAlert = false;
                            handShake = false;
                        } else { 
                            break;
                        }
                    }

                    if (System.currentTimeMillis() >= timeoutExpiredMs) {
                        timeout = true;
                        break;
                    }

                    //Stop listening if handshake failure or application data seen
                   if(finished || failed) break;
                    if(failed) break;
                }

                if(finished) {System.out.println("HANDSHAKE SUCCEEDED - likely app does not check" 
                        + " hostname of pinned certificate");
                outLog.println("HANDSHAKE SUCCEEDED - likely app does not check" 
                        + " hostname of pinned certificate");}
                if(failed) {System.out.println("HANDSHAKE FAILED - app does not accept alternate certificate from " + this.forwardHost);
                    outLog.println("HANDSHAKE FAILED - app does not accept alternate certificate " + this.forwardHost);}
                if(timeout) {System.out.println("HANDSHAKE TIMEOUT - likely app does not accept certificate from " + this.forwardHost);
                    outLog.println("HANDSHAKE TIMEOUT - likely app does not accept certificate from " + this.forwardHost);}


            } catch (InterruptedException | IOException e) {
                if(e instanceof IOException) {
                    System.out.println(e.getMessage());
                    e.printStackTrace();
                    outLog.println(e.getMessage());
                }
            } finally {
                try {
                    //Close all I/O streams and cut connection
                    clientInStream.close();
                    clientOutStream.close();
                    serverInStream.close();
                    serverOutStream.close();
                    clientConnection.close();
                    serverConnection.close();
                } catch (Exception e) {
                    outLog.println("Failed to close sockets");
                }
            }
        }

        public void setForwardHost(String forwardHost) {
			this.forwardHost = forwardHost;
		}
        
        public void setRealHost(String realHost) {
			this.realHost = realHost;
		}

		private String extractSNI(byte[] data) {
        	
        	try {
        		// 1 byte message type
        	// 3 bytes length
        	// 2 bytes version
        	// 32 random value
        	int index = 38;
        	// 1 byte len val to skip
        	int skipLen = data[index++] & 0xff;
        	index+=skipLen;
        	// 2 byte len val to skip
        	skipLen = ((data[index++] & 0xff) << 8) | (data[index++] & 0xff);
        	index+=skipLen;
        	// 1 byte len val to skip
        	skipLen = data[index++] & 0xff;
        	index+=skipLen;
        	// extenssions length
        	int extLen = ((data[index++] & 0xff) << 8) | (data[index++] & 0xff);
        	while(index < data.length) {
       	    	if(data[index++] == 0 && data[index++] == 0) {
       	    		//Extract SNI
					int totalSNILen = ((data[index++] & 0xff) << 8) | (data[index++] & 0xff);
					int firstSNILen = ((data[index++] & 0xff) << 8) | (data[index++] & 0xff);
					//skip type
					index++;
					int sniLen = ((data[index++] & 0xff) << 8) | (data[index++] & 0xff);
					return new String(Arrays.copyOfRange(data, index, index+sniLen));
       	    	} else {
					skipLen = ((data[index++] & 0xff) << 8) | (data[index++] & 0xff);
					index+=skipLen;
       	    	}
       	    }
        	
			return null;
        	} catch(Exception e) {
        		return null;
        	}
		}

		//Fill the maps with alert and handshake messages specified in RFC5246
        private void fillMaps() {

            alertMap.put(0, "CLOSE_NOTIFY");
            alertMap.put(10, "UNEXPECTED_MESSAGE");
            alertMap.put(20, "BAD_RECORD_MAC");
            alertMap.put(21, "DECRYPTION_FAILED");
            alertMap.put(22, "RECORD_OVERFLOW");
            alertMap.put(30, "DECOMPRESSION_FAILURE");
            alertMap.put(40, "HANDSHAKE_FAILURE");
            alertMap.put(41, "NO_CERTIFICATE");
            alertMap.put(42, "BAD_CERTIFICATE");
            alertMap.put(43, "UNSUPPORTED_CERTIFICATE");
            alertMap.put(44, "CERTIFICATE_REVOKED");
            alertMap.put(45, "CERTIFICATE_EXPIRED");
            alertMap.put(46, "CERTIFICATE_UNKNOWN");
            alertMap.put(47, "ILLEGAL_PARAMETER");
            alertMap.put(48, "UNKNOWN_CA");
            alertMap.put(49, "ACCESS_DENIED");
            alertMap.put(50, "DECODE_ERROR");
            alertMap.put(51, "DECRYPT_ERROR");
            alertMap.put(60, "EXPORT_RESTRICTION");
            alertMap.put(70, "PROTOCOL_VERSION");
            alertMap.put(71, "INSUFFICIENT_SECURITY");
            alertMap.put(80, "INTERNAL_ERROR");
            alertMap.put(90, "USER_CANCELLED");
            alertMap.put(100, "NO_RENEGOTIATION");
            alertMap.put(110, "UNSUPPORTED_EXTENSION");

            handShakeMap.put(0, "HELLO_REQUEST");
            handShakeMap.put(1, "CLIENT_HELLO");
            handShakeMap.put(2, "SERVER_HELLO");
            handShakeMap.put(4, "NEW_SESSION_TICKET");
            handShakeMap.put(11, "CERTIFICATE");
            handShakeMap.put(12, "SERVER_KEY_EXCHANGE");
            handShakeMap.put(13, "CERTIFICATE_REQUEST");
            handShakeMap.put(14, "SERVER_HELLO_DONE");
            handShakeMap.put(15, "CERTIFICATE_VERIFY");
            handShakeMap.put(16, "CLIENT_KEY_EXCHANGE");
            handShakeMap.put(20, "FINISHED");
            handShakeMap.put(22, "CERTIFICATE_STATUS");

        }
    }
}

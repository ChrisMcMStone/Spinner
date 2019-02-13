/**
 * A DNS server that serves forged DNS records for spoofing DNS. 
 * Requests for whitelisted domains are served legitimate response.
 * 
 * Tom Chothia & Chris McMahon Stone (c.mcmahon-stone@cs.bham.ac.uk)
 */

import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.util.*;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.UnknownHostException;

public class FakeDNS implements Runnable {

    private int portNo = 53;

    //verbose = 0: print nothing
    //verbose = 1: print spoofed requests
    //verbose = 2: print spoofed, dropped and allowed requests
    //verbose = 3: print spoofed, dropped and allowed requests and DNS details
    private int verbose;

    //Realistic looking Flags,# or Qus and RRs info for a DNS response
    private byte[] FlagsQusAndRRsInfo = Utils.hexStringToByteArray("81800001000100000000");
    //Realistic looking name, type and class info for a DNS response
    private byte[] nameTypeClass =  Utils.hexStringToByteArray("c00c00010001");
    // time to live of 10 seconds
    private byte[] ttl =  Utils.hexStringToByteArray("0000000a");
    // The address of a real DNS server.
    private String realDNSserver;

    // allowList will get the real IP address returned from the "realDNSserver".
    private String[] allowList;
    private String defaultSpoofIP;
    private MITM mitm; 
    private PrintWriter outLog;
    private String redirectHost;
    private boolean dnsOnly;
    private boolean passthrough;
    private String censysID;
    private String censysSecret;

    public FakeDNS(MITM mitm, int verbose, PrintWriter outLog, String redirectHost, boolean dnsOnly, boolean passthrough, Config config) {
        this.mitm = mitm;
        this.verbose = verbose;
        this.outLog = outLog;
        this.redirectHost = redirectHost;
	if(!dnsOnly) {
	    mitm.setForwardingHost(redirectHost);
	}
        this.dnsOnly = dnsOnly;
        this.passthrough = passthrough;
        this.realDNSserver=config.dnsIP;
        this.allowList=config.allowList;
        this.censysID = config.censysID;
        this.censysSecret = config.censysSecret;
    }

    public void run() {
        DatagramSocket sock = null;
        try {
            //Get IP address of MITM
            Enumeration<NetworkInterface> en = NetworkInterface.getNetworkInterfaces();
            while(en.hasMoreElements()){
                NetworkInterface iface = en.nextElement();
                if (iface.isLoopback() || !iface.isUp()) continue;
                Enumeration<InetAddress> ee = iface.getInetAddresses();
                while(ee.hasMoreElements()) {
                    InetAddress ia= ee.nextElement();
                    if (ia instanceof Inet6Address) continue;
                    defaultSpoofIP = ia.getHostAddress();
                    break;
                }
            }
            //Open a UDP port
            sock = new DatagramSocket(portNo);
            sock.setSoTimeout(500);
            byte[] buffer = new byte[128];
            DatagramPacket incoming = new DatagramPacket(buffer, buffer.length);
            if (verbose>0) System.out.println("- Listening on UDP port: "+portNo);

            while(true) {
                if(Thread.currentThread().isInterrupted()) throw new InterruptedException();
                if(dnsOnly || mitm.isConnectionWaiting()) {
                    // Listen for a request
                    try { sock.receive(incoming); } catch (SocketTimeoutException e) {continue;}
                    byte[] origDNSrequest = incoming.getData();

                    //Find the port and IP of sender
                    int portFrom = incoming.getPort();
                    InetAddress ipAddressFrom = incoming.getAddress();

                    //Parse the DNS request
                    String urlRequested = parseDNSrequest(origDNSrequest);

                    int resultInt = Utils.stringListMatch(urlRequested,allowList);
                    if (resultInt<0) {
                        if (verbose>1) System.out.println("- Requested URL: "+urlRequested+" on allow list. Returning real DNS response.");
                        outLog.println("- Requested URL: "+urlRequested+" on allow list. Returning real DNS response.");
                        // Request real response from the real DNS server
                        byte[] dnsReply = getRealDNSresponse(origDNSrequest);
                        // Forward that response back to the original requester.
                        DatagramPacket reply = new DatagramPacket(dnsReply,dnsReply.length,ipAddressFrom,portFrom);
                        sock.send(reply);
                    } else {
                        if (verbose>0) System.out.println("- Requested URL: "+urlRequested+" default action. Sending default IP: "+defaultSpoofIP);
                        outLog.println("- Requested URL: "+urlRequested+" default action. Sending default IP: "+defaultSpoofIP);
                        if(passthrough || alternateHostResponse(urlRequested)) {
                            //Send a spoofed address back to the original requester.
                            byte[] response = formDNSresponse(origDNSrequest, urlRequested.length()+1, defaultSpoofIP);
                            DatagramPacket reply = new DatagramPacket(response,response.length,ipAddressFrom,portFrom);
                            sock.send(reply);
                        }
                    }
                }
            }
        } catch (InterruptedException | IOException e) {
            if(e instanceof IOException) {
                System.out.println(e.getMessage());
                outLog.println(e.getMessage());
            }
        } finally {
            if(sock != null) sock.close();
        }
    }

    private boolean alternateHostResponse(String urlRequested) {
        if(dnsOnly || mitm.getRedirectHosts().containsKey(urlRequested)) return true;
        Cert[] certs = CheckCertificate.getCertificates(urlRequested);
        if(certs != null && certs.length > 1) {
            if(verbose > 1) System.out.println("- CN of Issuer for "+urlRequested + " = " + certs[1].getCN());
            outLog.println("- CN of Issuer for "+urlRequested + " = " + certs[1].getCN());
            mitm.addRealLeafCert(urlRequested, certs[0].getDer());
            mitm.addRealIssuerCert(urlRequested, certs[1].getDer());
            if(this.redirectHost != null) {
                mitm.addRedirectHost(urlRequested, this.redirectHost);
                mitm.setForwardingHost(this.redirectHost);
                mitm.setRealHost(urlRequested);
            } else {
                String alternateHost;
                if(!mitm.getCachedAlternateHosts().containsKey(urlRequested)) {
                    alternateHost = CheckCertificate.censysLookup(urlRequested, certs[1].getCN(), censysID, censysSecret);
                    if(alternateHost == null) {
                        System.out.println("- No alternate hosts for given " + urlRequested + ". Dropping request...");
                        outLog.println("- No alternate hosts for given " + urlRequested + ". Dropping request...");
                        return false;
                    }
                    mitm.addCachedAlternateHost(urlRequested, alternateHost);
                } else {
                    alternateHost = mitm.getCachedAlternateHosts().get(urlRequested);
                }
                mitm.addRedirectHost(urlRequested, alternateHost);
                mitm.setForwardingHost(alternateHost);
                mitm.setRealHost(urlRequested);
            }
            //			if (verbose>0) System.out.println("- Forwarding " + urlRequested + " traffic to: " + mitm.getForwardingHost());
            //			outLog.println("- Forwarding " + urlRequested + " traffic to: " + mitm.getForwardingHost());
            return true;
        } else {
            System.out.println("- Less than two certificates in chain. Dropping request...");
            outLog.println("- Less than two certificates in chain. Dropping request...");
        }
        return false;
    }

    /**
     * @param data e.g. a DNS request 
     * @return the response received from sending  data over socket
     */
    // sock is a UDP socket and data is a DNS request.
    public byte[] getRealDNSresponse(byte[] data)
        throws UnknownHostException, IOException {
        DatagramSocket realDNSsocket = new DatagramSocket();
        DatagramPacket requestPacket = new DatagramPacket(data,data.length,InetAddress.getByName(realDNSserver),53);
        realDNSsocket.send(requestPacket);
        byte[] dnsReply = new byte[1024];
        DatagramPacket dnsReplyPacket = new DatagramPacket(dnsReply,dnsReply.length);
        realDNSsocket.receive(dnsReplyPacket);
        return dnsReply;
    }

    /**
     * @param dnsQuery A DNS query
     * @param urlLength The length of the URL in that query
     * @param theSpoofIP An IP address
     * @return A DNS response that will answer the query with the IP address "theSpoofIP"
     */
    public byte[] formDNSresponse(byte[] dnsQuery, int urlLength,
            String theSpoofIP) {
        byte[] response = new byte[urlLength+33];
        System.arraycopy(dnsQuery, 0, response, 0, 2);  //The Transaction ID:
        System.arraycopy(FlagsQusAndRRsInfo, 0, response, 2, 10);
        System.arraycopy(dnsQuery, 12, response, 12, urlLength+5); //The query
        //The Answer
        System.arraycopy(nameTypeClass, 0, response, urlLength+17, 6); 
        System.arraycopy(ttl, 0, response, urlLength+23, 4); 
        //Length of IP address is 4 bytes
        response[urlLength+27]= 0x00;
        response[urlLength+28]= 0x04;
        //The Address
        String[] IPparts = theSpoofIP.split("\\.");
        response[urlLength+29]= (byte)(Integer.parseInt(IPparts[0]));
        response[urlLength+30]= (byte)(Integer.parseInt(IPparts[1]));
        response[urlLength+31]= (byte)(Integer.parseInt(IPparts[2]));
        response[urlLength+32]= (byte)(Integer.parseInt(IPparts[3]));
        return response;
    }

    /**
     * This does not support more than one URL in the query
     *
     * @param data A DNS query
     * @return the URL asked for in the query as a String
     */
    public String parseDNSrequest(byte[] data) {
        if (verbose>2) {
            System.out.println(Utils.byteArrayToHexString(data));
            System.out.println("- Transaction ID:"+Utils.byteArrayToHexString(data,0,2));
            System.out.println("- Flags:"+Utils.byteArrayToHexString(data,2,4));
            System.out.println("- Questions:"+Utils.byteArrayToHexString(data,4,6));
            System.out.println("- Answers RRs:"+Utils.byteArrayToHexString(data,6,8));
            System.out.println("- Authority RRs:"+Utils.byteArrayToHexString(data,8,10));
            System.out.println("- Additional RRs:"+Utils.byteArrayToHexString(data,10,12));
        }

        //Find the domain name being requested
        ArrayList<String> urlList = new ArrayList<String>();
        int pos = 12;
        Integer length = new Integer(data[pos]);
        int totalLength = length.intValue();
        while (length!=0) {
            String part = new String(data, pos+1,length);
            urlList.add(part);
            pos=pos+length+1;
            length = new Integer(data[pos]);
            totalLength = totalLength+length.intValue()+1;
        }
        String urlString=urlList.get(0);
        for (int i =1;i<urlList.size();i++) {
            urlString=urlString+"."+urlList.get(i);
        }
        return urlString;
    }

}

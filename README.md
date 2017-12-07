# Spinner: Semi-Automatic Detection of Pinning without Hostname verification

Tool to enable black box detection of applications that pin to non-leaf TLS certificates and fail to carry out hostname verification. It can also be used to detect apps that have the same issue but do not pin, or indeed apps that will accept any certificate (such as self-signed). 

Spinner analyses the certificate chain of the requested domains and redirects TLS traffic to other sites, which it finds on Censys.io, that use the same certificate chain. The handshake is then proxied to determine if encrypted application data is sent by the app to the domain that the app is not expecting.

For more details see our [paper](http://www.cs.bham.ac.uk/~garciaf/publications/spinner.pdf)


**To compile:**

On Linux: ```javac -cp .:libs/* *.java```

On Windows: ```javac -cp ".;libs/*" *.java```

**To run:**

On Linux: ```sudo java -cp .:libs/* Launcher --help```

On Windows: ```java -cp ".;libs/*" Launcher --help```


(Note: root is required as a TLS and DNS server are ran on privileged ports)

The program requires a config file which contains the IP address of the DNS server on your network, and the credentials to use with Censys.io. You will need to sign up for an account here https://censys.io/register. 

**Example usage**

Run the tool with config details specified in the file ```config``` and ignore connections to domains listed in ```whitelist```

```sudo java -cp .:libs/* Launcher -c config -w whitelist```

Run the tool without using Censys by manually specifying a redirect domain. 

```sudo java -cp .:libs/* Launcher -m google.com```


**Disclaimer: This tool is intended for research use, and is currently undergoing further development. We welcome any feedback which can be provided by raising issues or pull requests. **



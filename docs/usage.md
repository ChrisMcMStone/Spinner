

# Compilation and Usage Instructions


**To compile:**

On Linux: ```javac -cp .:libs/* *.java```

On Windows: ```javac -cp ".;libs/*" *.java```

**Set up:**

Spinner needs to be able to Man-in-the-Middle DNS requests and TLS traffic. To this end, it sets up a DNS and TLS proxy running on ports 53 and 443 respectively. To direct traffic from your testing device to Spinner:

* Set DNS of device to use IP of machine running Spinner e.g. In android: WiFi -> Modify Network -> Advanced -> IP Settings, Static -> DNS

or

* Set up a Wi-Fi access point on the device running Spinner. In Linux this can be done with [hostapd](https://w1.fi/hostapd/). Connect testing device to the access point running Spinner. 


**To run:**

On Linux: ```sudo java -cp .:libs/* Launcher --help```

On Windows: ```java -cp ".;libs/*" Launcher --help```


(Note: root is required as a TLS and DNS server are ran on privileged ports)

The program requires a config file which contains the IP address of the DNS server on your network, and the credentials to use with Censys.io. You will need to sign up for an account here <https://censys.io/register>.


**Example usage**

Run the tool with config details specified in the file ```config``` and ignore connections to domains listed in the file ```domain_whitelist```

```sudo java -cp .:libs/* Launcher -c config -w domain_whitelist```

Run the tool without using Censys by manually specifying a redirect domain. 

```sudo java -cp .:libs/* Launcher -m google.com```

If your app is detected as vulnerable. You can narrow down the exact hostname verification vulnerability by using the ```-m``` option to check if:

* The app accepts self-signed certificates by redirecting the traffic to ```self-signed.badssl.com```

* The app accepts any valid certificate (but for wrong hostname) by redirecting the traffic to ```wrong.host.badssl.com```

<br><br>

**Disclaimer**: This tool is intended for research use, and is currently undergoing further development. We welcome any feedback which can be provided by raising issues or pull requests.

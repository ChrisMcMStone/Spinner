

## Compilation and Usage Instructions


**To compile:**

On Linux: ```javac -cp .:libs/* *.java```

On Windows: ```javac -cp ".;libs/*" *.java```

**Set up:**

Either:
* Set DNS of mobile device to use IP of machine running Spinner e.g. In android: WiFi -> Modify Network -> Advanced -> IP Settings, Static -> DNS

or

* Run Spinner on machine with access point e.g. hostapd. Connect testing device to AP running Spinner. 

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


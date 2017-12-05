# Spinner: Semi-Automatic Detection of Pinning without Hostname verification

**To compile:**

On Linux: ```javac -cp .:libs/* *.java```

On Windows: ```javac -cp ".;libs/*" *.java```

**To run:**

On Linux: ```sudo java -cp .:libs/* Launcher --help```

On Windows: ```sudo java -cp ".;libs/*" Launcher --help```


(Note: root is required as a TLS and DNS server are ran on privileged ports)

The program requires a "config" file (which I have provided) which
contains the IP address of the DNS server on your network, and the
credentials to use with Censys.io. You will need to have an account 

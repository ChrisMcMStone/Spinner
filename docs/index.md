---
youtubeId: yUZ1gmhERfs
---


# Spinner: Semi-Automatic Detection of Pinning without Hostname verification

Tool to enable black box detection of applications that pin to non-leaf TLS certificates and fail to carry out hostname verification. It can also be used to detect apps that have the same issue but do not pin, or indeed apps that will accept any certificate (such as self-signed). 

Spinner analyses the certificate chain of the requested domains and redirects TLS traffic to other sites, which it finds on Censys.io, that use the same certificate chain. The handshake is then proxied to determine if encrypted application data is sent by the app to the domain that the app is not expecting.

For more details see our [paper](http://www.cs.bham.ac.uk/~garciaf/publications/spinner.pdf)

{% include youtubePlayer.html id=page.youtubeId %}


**Disclaimer**: This tool is intended for research use, and is currently undergoing further development. We welcome any feedback which can be provided by raising issues or pull requests.



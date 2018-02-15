
# Discovered Vulnerabilites

In [this](https://www.cs.bham.ac.uk/~tpc/Papers/spinner.pdf) paper, we describe our results of testing 400 high security applications using Spinner. These included banking, trading, VPN and cryptocurrency apps. We found 9 apps in total that pinned to a non-leaf TLS certificate but failed to carry out hostname verification. This rendered them vulnerable to Man-in-the-Middle attacks. 

| App name | No. of Downloads | Platform |
|----------|----|----|
| Bank of America Health | 100k - 500k | Android |
| TunnelBear VPN | 1m - 5m | Android |
| Meezan Bank | 10k - 50k | Android |
| Smile Bank | 10k - 50k | Android |
| HSBC | 5m - 10m | iOS |
| HSBC Business | 10k - 50k | iOS |
| HSBC Identity | 10k - 50k | iOS |
| HSBCnet | 10k - 50k | iOS |
| HSBC Private | 10k - 50k | iOS |


Of notable impact was HSBC's set of iOS apps. We note that this vulnerability affected their entire global app base, which consists of apps from 30 countries they operate in. 

We also discovered numerous apps that were not pinning but also did not verify certificate hostnames correctly. For a full list of affected apps, see page 8 of our [paper](https://www.cs.bham.ac.uk/~tpc/Papers/spinner.pdf).

### Example affected APKs

Below we link to hosted APKs for apps affected by the pinning without hostname verification vulnerability. These can be used to demonstrate Spinner's detection of vulnerable apps. 

* [TunnelBear VPN v139](https://www.apkmirror.com/apk/tunnelbear-inc/tunnelbear-vpn/tunnelbear-vpn-v139-release/tunnelbear-vpn-v139-android-apk-download/)
* [Meezan Bank v1.3.1](https://meezan-mobile-banking.en.aptoide.com)

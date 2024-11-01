---
layout: post
title: Locating IPs that respond to a URL
date: 2024-10-31 21:00:00.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- Offensive Security
tags:
- Offensive Security
- WAF
- Bypass WAF
- Pentest
author: Helvio Junior (m4v3r1ck)
permalink: "/security/osint/locating-url-ips-bypass-waf/"
excerpt: "Perform the WAF bypass using Web Finder to locate addresses that respond to the site without WAF."
image:
  src: /assets/2024/10/e52cfdb1d4783a4b933ba33b548f54a4.png
  alt: Web Finder
---

## Introduction

Web Finder aims to assist in locating IP addresses that respond to a specific URL, thus enabling the WAF bypass.

## Technical Concept
When making an HTTP/S request to a host, the first step for the client is resolving the name to an IP address, followed by a direct connection to that IP. This procedure pertains to the Transport layer of the OSI model (Layer 4), where only the IP and port are involved. Once the TCP connection is successfully established, the client constructs an HTTP request header and sends it to the server. See the following example:

Assuming that a browser is directed to https://www.helviojunior.com.br (as shown in the curl command below), the client will first resolve the DNS name to the IP (which will result in 54.244.151.52) and then send the header as follows:

```bash
curl -k https://www.helviojunior.com.br
```

Header:

```
GET / HTTP/1.1
Host: www.helviojunior.com.br
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: pt-BR,pt;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Upgrade-Insecure-Requests: 1
Te: trailers
Connection: close
```

As we can see in the 'Host' header, we have the full name of the server. With the advent of HTTP 1.1 and onwards, the server considers this field to internally route which site it should respond to. If the server is prepared to respond to this host (www.helviojunior.com.br), it will do so.

However, we can perform the same process differently by directing the client to connect to a specific IP address and forcing the host in the HTTP header, as shown in the command below:

```bash
curl -k -H 'Host: www.helviojunior.com.br' https://54.244.151.52
```

In this way, the TCP connection will necessarily occur to the IP 54.244.151.52 regardless of the DNS resolution; however, the HTTP header will send the host www.helviojunior.com.br. This way, we will obtain the same result in response.

However, we can change the IP address to any other, such as 10.10.10.10. If the server at this IP exists and is prepared to respond to the site www.helviojunior.com.br, the response (HTTP status code and size) will be the same.

```bash
curl -k -H 'Host: www.helviojunior.com.br' https://10.10.10.10
```

Thus, we can use this technique to provide a list of IPs and check if they are configured to respond to a specific site.

## Setup

### Installing pipx

> We recommend using `pipx` over `pip` for system-wide installations.
{: .prompt-warning }

```bash
python3 -m pip install pipx
python3 -m pipx ensurepath
```

### Installing Web Finder

```bash
python3 -m pipx install wafwebfinder
```

## Practical Example

In this tutorial, we will conduct the test with the service from X (formerly Twitter). The motivation for this exercise stems from the fact that it recently transitioned its service to a CDN to avoid blocks imposed in Brazil.

### IP Enumeration

The first necessary step is to collect/enumerate possible IPs. For this process, we will use three different techniques:

1. Active enumeration via DNS brute force
2. Passive enumeration through VirusTotal
3. Passive enumeration through Shodan

### EnumDNS

`enumdns` is a script created by me and is available at [https://github.com/helviojunior/libs/blob/master/python/enumdns.py](https://github.com/helviojunior/libs/blob/master/python/enumdns.py).

Download the SecList (wordlist we will use).

```bash
mkdir -p /usr/share/wordlists/
cd /usr/share/wordlists/
git clone https://github.com/danielmiessler/SecLists
```

```bash
cd ~
wget https://raw.githubusercontent.com/helviojunior/libs/master/python/enumdns.py
python3 enumdns.py -d x.com -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -o enumdns.txt
```

[![]({{site.baseurl}}/assets/2024/10/190a4c7725bd4eced57d42c1e62a331c.png)]({{site.baseurl}}/assets/2024/10/190a4c7725bd4eced57d42c1e62a331c.png)

> Keep the generated file `enumdns.txt` so we can later filter the IPs.
{: .prompt-tip }

### Virus Total

Access [VirusTotal](https://www.virustotal.com/) and enter the desired URL, perform the search, and then click on **Relations**.

[![]({{site.baseurl}}/assets/2024/10/77d12c98a1c531556aba5b6932152307.png)]({{site.baseurl}}/assets/2024/10/77d12c98a1c531556aba5b6932152307.png)

In the **Relations** tab, we will see several IP addresses.

[![]({{site.baseurl}}/assets/2024/10/aabac0b30c726f5f712a93d426f1b351.png)]({{site.baseurl}}/assets/2024/10/aabac0b30c726f5f712a93d426f1b351.png)

Select all the text/HTML from the site, copy it, and paste it into a text file.

> Don’t worry if other texts appear in this process, as we will filter only the IP addresses later.
{: .prompt-tip }

[![]({{site.baseurl}}/assets/2024/10/4444a223d6c4a4d00fd6e31befb70836.png)]({{site.baseurl}}/assets/2024/10/4444a223d6c4a4d00fd6e31befb70836.png)

### Shodan

View all the addresses listed by Shodan through the URL `https://www.shodan.io/domain/{DOMAIN}`, replacing `{DOMAIN}` with the desired domain. Example: `https://www.shodan.io/domain/x.com`

[![]({{site.baseurl}}/assets/2024/10/618f3f3a0794120172d8cc00c2f80aa2.png)]({{site.baseurl}}/assets/2024/10/618f3f3a0794120172d8cc00c2f80aa2.png)

Select all the text/HTML from the site, copy it, and paste it into a text file.

> Again, don’t worry if other texts appear in this process, as we will filter only the IP addresses later.
{: .prompt-tip }


[![]({{site.baseurl}}/assets/2024/10/37a2c22f6076173c08a89280b5904a8d.png)]({{site.baseurl}}/assets/2024/10/37a2c22f6076173c08a89280b5904a8d.png)


### Filtering Only IPs

Save all the previously obtained content in a single text file.

For illustration purposes, here’s a `grep` command to filter only the lines with IPv4 addresses.

[![]({{site.baseurl}}/assets/2024/10/e60c561c311d427950957071b85c32ae.png)]({{site.baseurl}}/assets/2024/10/e60c561c311d427950957071b85c32ae.png)


```bash
cat tmp.txt | grep -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'
```

Now we will obtain the IP addresses, sort them, and filter for unique addresses.

```bash
cat tmp.txt | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | sort -u > tst.txt
```

[![]({{site.baseurl}}/assets/2024/10/d15cfa665415a650552fbe06a6a90514.png)]({{site.baseurl}}/assets/2024/10/d15cfa665415a650552fbe06a6a90514.png)

## Expanding the Search

In some scenarios, it may be necessary to expand the search to all `/24` subnets of the found IPs.

> This step is not mandatory, but it can be important to broaden the search and find other addresses that were not listed in the previous steps. In a cloud environment, many IPs may come up that likely do not fall within the scope of the test, but in an on-premises environment, the accuracy is quite high.
{: .prompt-tip }

To do this, we will extract only the subnets:

```bash
for net in $(cat *.txt | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.'):; do echo "${net}0/24"; done | sort -u > subnets.txt
```

Then perform an NMAP scan to locate the addresses that respond to HTTP and HTTPS.

```bash
nmap -Pn -v -T4 -sTV -p80,443 -iL subnets.txt | tee -a nmap_subnets_1.txt
```

After finishing, we can filter the addresses.

```bash
cat nmap_subnets_1.txt | grep 'open port' | grep '443\|80' | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | sort -u > tst.txt
```

## Using WebFinder

Now that we have a list of IPs, we can use it to check which servers respond to the desired service.

```bash
webfinder -t https://x.com/ -ip tst.txt -o x.txt --random-agent
```

> The command above will respect the protocol specified by the URL (`http` or `https`). If you want to search both protocols, just use the `--check-both` parameter.
{: .prompt-tip }

### Blind Check

In its default search mode, Web Finder will first connect to the original site and obtain the return code as well as the size of the response body. This process aims to understand the pattern of the original site before searching for the same pattern directly on the provided IP addresses.

However, there are some scenarios where access to the original site is not possible for various reasons, such as blocks, network connectivity, etc. In these cases, Web Finder has a `--static` parameter that allows you to specify the expected return code (e.g., 200, 204, 404, 500, etc.) along with (or without) the expected response size.

Using the previous request as a basis, which returned a `200` code with a size of `2610 bytes`, we can execute it with two variants:

1. Only the status code: `webfinder -t https://x.com/ -ip tst.txt -o x.txt --random-agent --static 200`
2. Status code + size: `webfinder -t https://x.com/ -ip tst.txt -o x.txt --random-agent --static 200:2610`


[![]({{site.baseurl}}/assets/2024/10/1b37ddb9f2e6a31e014c213e3dcd93da.png)]({{site.baseurl}}/assets/2024/10/1b37ddb9f2e6a31e014c213e3dcd93da.png)

[![]({{site.baseurl}}/assets/2024/10/08b7be65907ca0cd20412d6525e3bd40.png)]({{site.baseurl}}/assets/2024/10/08b7be65907ca0cd20412d6525e3bd40.png)

> Using `--static` with only the return code can lead to false positives, as the identification of the return may not be precise.
{: .prompt-warning }

## Conclusion

As we have seen in this article, it is possible to obtain the IP addresses that respond to a specific service.

Additionally, the `webfinder` tool assists in this process and illustrates if the found IP is protected by a CDN and/or WAF.

[![]({{site.baseurl}}/assets/2024/10/5ac920de9474360e1ecbb465869b3c2d.png)]({{site.baseurl}}/assets/2024/10/5ac920de9474360e1ecbb465869b3c2d.png)

## References:

- [Source Code](https://github.com/helviojunior/webfinder)
- [PyPi - Python Package Index](https://pypi.org/project/WafWebFinder/)






---
layout: post
title: Hashcat error 'Already an instance running on pid xxx'
date: 2018-07-15 20:50:16.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories: []
tags: []
author: Helvio Junior (m4v3r1ck)
permalink: "/uncategorized/hashcat-error-already-an-instance-running-on-pid-xxx/"
---

If you are not running other instance of netcat just remove pid file running the command below

```bash
rm -rf ~/.hashcat/sessions/hashcat.pid
```

---
layout: post
title: Enviando alerta do Zabbix via Gtalk
date: 2013-05-23 12:30:02.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- Desenvolvimento
- IT
- Monitoramento
- Zabbix
tags: []
author: Helvio Junior (m4v3r1ck)
permalink: "/it/devel/enviando-alerta-do-zabbix-via-gtalk/"
---

Este post tem o objetivo de demonstrar como criar um script para que o Zabbix possa enviar os alertas via Gtalk.

<!--more-->

**Instalação dos pre-requisitos**

```bash
apt-get install python python-xmpp python-dnspython
```

**Criação do script**

Verificar o local de armazenamento dos script no arquivo de configuração do zabbix, o parâmetro a ser verificado é AlertScriptsPath. No meu caso está em **/usr/lib/zabbix/alertscripts**

Crie o arquivo, nomeado **gtalk.py**, com o conteúdo abaixo no local indicado. No meu caso em **/usr/lib/zabbix/alertscripts/gtalk.py**

```python
#!/usr/bin/python -W ignore::DeprecationWarning
import sys, os, xmpp, getopt, syslog

def main(argv):
	login="your_email@gmail.com"
	pwd="xxxxxx"
	_debug = 0

	if len(sys.argv) < 3:
		usage()
		sys.exit(2)

	#log dos parametros recebidos
	#log(' '.join(sys.argv[1:]))

	rcptto=None
	subject=None
	msg=None

	rcptto=sys.argv[1]
	subject=sys.argv[2]
	msg=sys.argv[3]

	if subject != None and msg == None:
		msg = subject;
		subject = None;

	if rcptto == None or msg == None:
		usage()
		sys.exit(2)

	log(msg)

	print "Starting process..."

	def presenceHandler(conn, presence):
		if presence:
			if presence.getType() == "subscribe":
				cl.PresenceManager.ApproveSubscriptionRequest(pres.From)

	login=xmpp.protocol.JID(login)

	if _debug == 1:
		cl=xmpp.Client(login.getDomain())
	else:
		cl=xmpp.Client(login.getDomain(),debug=[])

	print "Connecting..."
	if cl.connect( server=('google.com',5222)  ) == "":
			print "not connected"
			sys.exit(0)

	print "Authentication..."
	if cl.auth(login.getNode(),pwd) == None:
			print "authentication failed"
			sys.exit(0)

	# habilita que este cliente aceite automaticamente requisicao de contato
	#cl.RegisterHandler('presence',presenceHandler)
	#cl.sendInitPresence()

	print "Add user "+rcptto
	pres = xmpp.Presence(to=rcptto, typ='subscribe')
	cl.send(pres)

	print "Sending message to "+rcptto
	cl.send(xmpp.protocol.Message(rcptto,msg,"chat"))
	cl.disconnect()

	print "Message Sent!"

def usage():
	print "Usage:  {-d} [to] [subject] [body]"
	print ""
	print "Options:"
	print "  [to]	destination of messages"
	print "  [subject]	subect of message"
	print "  [body]	destination of messages"

def log(text):
	syslog.syslog(syslog.LOG_ERR, text)

if __name__ == "__main__":
	main(sys.argv[1:])
```

Altere as linhas abaixo (no script) para o e-mail e senha que serão a origem do Gtalk

```python
login="your_email@gmail.com"
pwd="xxxxxx"
```

**Defina as permições para este arquivo**

```bash
chown -R zabbix:zabbix /usr/lib/zabbix/alertscripts/
chmod +x /usr/lib/zabbix/alertscripts/gtalk.py
```

Realize um teste de execução do script com o comando abaixo, apenas alterando seu e-mail.

```bash
sudo -u zabbix /usr/lib/zabbix/alertscripts/gtalk.py seu_email@gmail.com "Teste 001" "Mensagem de teste Gtalk"
```

**Configurando o Zabbix para enviar os alertas através deste script**

Vá em **Administration** > **Media Types**

[![001]({{ site.baseurl }}/assets/2013/05/0011.png)]({{ site.baseurl }}/assets/2013/05/0011.png)

Clique em **Create Media** e preencha os campos conforme demonstrado abaixo e clique em **Save**

[![002]({{ site.baseurl }}/assets/2013/05/0021.png)]({{ site.baseurl }}/assets/2013/05/0021.png)

Vá em **Administration** > **Users**, selecione o usuário que deseja receber o alerta através do Gtalk, clique em **Media** e depois em **Add**

![003]({{ site.baseurl }}/assets/2013/05/0031.png)

Preencha as informações, alterando o **Type** para **Gtalk** e o **Send to** para o e-mail do gmail que receberá via Gtalk e clique em **Add**.

[![004]({{ site.baseurl }}/assets/2013/05/0041.png)]({{ site.baseurl }}/assets/2013/05/0041.png)

Pronto, seu usuário será alertado via gtalk.

install:
	gcc client.c -o vpnClient -lssl -lcrypto
	gcc server.c -o vpnServer -lssl -lcrypto

clean:
	rm -f vpnClient
	rm -f vpnServer

Webview exposes remote debugging using the `setWebContentsDebuggingEnabled` API. The API was introduced in API 19.

Webview debugging uses the Chrome Debug Protocol and is exposed using an abstract named unix socket. The socket is either name `webview_devtools_remote` or `webview_devtools_remote_<pid>`.

To confirm that socket is exposed on your device, you may use the `netstat -untapexW` command and search for your target application or the `@` sign, used to denote abstract sockets.

Abstract sockets do not use file system permissions to enforce access and are therefore accessible to all applications on the device.

To demonstrate access to the socket, you may use the `socat` binary to expose the abstract socket:

```shell
./socat TCP-LISTEN:9999,fork ABSTRACT:webview_devtools_remote_3483
```

The 9999 port can either be accessed locally or for testing purposes, be forwarded using adb:

```shell
adb forward tcp:9999 tcp:9999
```

To access the remote protocol, use the Chrome Debug Protocol client, like `pychrome`:


=== "Python"
	```python
	import pychrome
	
	# connect to webview on the exposed port.
	browser = pychrome.Browser(url="http://127.0.0.1:9999")
	t = browser.list_tab()[0]
	t.start()
	t.DOM.enable()
	
	# Access document.
	t.DOM.getDocument()
	```


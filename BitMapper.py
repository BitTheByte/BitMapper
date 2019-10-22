from burp import IBurpExtender
from burp import IHttpListener
from burp import ITab
import sys
import re

class BurpExtender(IBurpExtender, IHttpListener, ITab):

    def registerExtenderCallbacks(self, callbacks):
        # Registering callbacks from burp api
        self.callbacks = callbacks
        self.callbacks.setExtensionName("BIT/Mapper")
        self.callbacks.registerHttpListener(self)

        # Redirect the stdout to burp stdout
        sys.stdout = self.callbacks.getStdout()
        
        # Saving IExtensionHelpers to use later
        self.helpers = self.callbacks.getHelpers()
        print("Loaded!")
        return

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            return

        request = messageInfo.getResponse()
        requestInfo = self.helpers.analyzeResponse(request)
        body = request[requestInfo.getBodyOffset():]
        headers = requestInfo.getHeaders()

        if str(messageInfo.url)[-3::] != ".js": return
        if "sourceMappingURL" in bytes(bytearray(body)):
            print("[DEBUG] Found sourceMappingURL :: " + unicode(messageInfo.url))
            return

        print("[DEBUG] Appending sourceMappingURL :: " + unicode(messageInfo.url))
        payload = u"//# sourceMappingURL=" + unicode(messageInfo.url) + u".map"
        for i,header in enumerate(headers):
            if "Content-Length" in header:
                headers[i] = "Content-Length: " + str( int(header.split(":")[1].strip()) + len(payload) )

        httpRequest = bytearray()
        httpRequest += bytearray('\n'.join(headers).encode("utf8"))
        httpRequest += bytearray('\n\n')
        httpRequest += bytearray(body)
        httpRequest += bytearray(payload.encode("utf8"))
        messageInfo.setResponse( bytes(httpRequest) )

        return

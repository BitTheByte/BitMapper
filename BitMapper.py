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

    def rm_integrity(self,body):
        for integrity in re.findall('integrity="(.*?)"',body):
            body = re.sub(integrity,'',body)
        return body

    def build_response(self,headers,content_length):
        for i,header in enumerate(headers):
            if "Content-Length" not in header:
                continue
            headers[i] = f"Content-Length: {str(content_length)}"

        httpRequest = bytearray()
        httpRequest += bytearray('\r\n'.join(headers).encode("utf8"))
        httpRequest += bytearray('\r\n'*2)
        return httpRequest

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            return

        request      = messageInfo.getResponse()
        requestInfo  = self.helpers.analyzeResponse(request)
        body         = request[requestInfo.getBodyOffset():]
        headers      = requestInfo.getHeaders()

        if str(messageInfo.url)[-3::] != ".js":
            body     = self.rm_integrity(body)
            response = self.build_response(headers,len(body))
            response += bytearray(body)
            messageInfo.setResponse( bytes(response) )
            return

        if "sourceMappingURL" in bytes(bytearray(body)):
            print(f"[DEBUG] Found sourceMappingURL :: {unicode(messageInfo.url)}")
            return

        payload = (
            f"//# sourceMappingURL={unicode(messageInfo.url)}.map"
            + u"\n//edited_by_bitmapper"
        )
        response =  self.build_response(headers, len(body) + len(payload) )
        response += bytearray(body)
        response += bytearray(payload.encode("utf8"))
        messageInfo.setResponse( bytes(response) )

        print(f"[DEBUG] Appended sourceMappingURL :: {unicode(messageInfo.url)}")
        return
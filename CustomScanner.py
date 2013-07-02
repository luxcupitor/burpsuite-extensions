'''
Custom Scanner 
-by @luxcupitor

example burp python extension
-passive scan check
-active scan check
-run check on proxy history and add issue to Scanner tab
'''
from burp import IBurpExtender
from burp import IScanIssue
from burp import IScannerCheck
from burp import IScannerInsertionPoint
from burp import ITab
from java.awt import Component;
from java.awt import FlowLayout;
from java.awt import Panel;
from java.awt.event import ActionEvent;
from java.awt.event import ActionListener;
from javax.swing import JButton;
from java.io import PrintWriter;
from array import array

class BurpExtender(IBurpExtender, ITab, IScannerCheck, IScannerInsertionPoint):

    # definitions
    EXTENSION_NAME="CustomScanner"

    def registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self._callbacks = callbacks
        
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
       
        # define stdout writer
        self._stdout = PrintWriter(callbacks.getStdout(), True) 
        self._stdout.println(self.EXTENSION_NAME + ' by @luxcupitor')
        self._stdout.println('================================')
        self._stdout.println('')
        self._stdout.println('TIP: Go to "Custom Scanner" tab and click "Execute on Proxy History"')
        self._stdout.println('to run the scanner checks on recently imported session files.')
        self._stdout.println('')
        # set our extension name
        callbacks.setExtensionName(self.EXTENSION_NAME)
        callbacks.registerScannerCheck(self)
        
        # add the custom tab and button to Burp's UI
        self._newpanel = Panel()
        self._newpanel.setLayout(FlowLayout())
        self._button = JButton("Execute on Proxy History", actionPerformed=self.checkProxyHistory)
        self._newpanel.add(self._button)
        callbacks.customizeUiComponent(self._newpanel)
        callbacks.addSuiteTab(self)

        return
    
    def getTabCaption(self):
      '''Name of our tab'''
      return self.EXTENSION_NAME

    def getUiComponent(self):
      '''return our panel and button we setup'''
      return self._newpanel

    def checkProxyHistory(self,msg):
      '''This is what gets executed when the button in our panel is clicked'''
      for proxyitem in self._callbacks.getProxyHistory():
        self.logScanIssue(proxyitem)

      return


    def getMatches(self, response, match):
      '''This finds our pattern match in the request/response and returns an int array'''
      start = 0
      count = 0
      matches = [array('i')]
      while start < len(response):
        start=self._helpers.indexOf(response, match, True, start, len(response))
        if start == -1:
          break
        try:
          matches[count]
        except:
          matches.append(array('i'))
        matches[count].append(start)
        matches[count].append(start+len(match))
        start += len(match)
        count += 1

      return matches


    def doPassiveScan(self, baseRequestResponse):
      '''This sets up our custom check and returns the issue a list array'''
      PATTERN="secretdata"
      ISSUE_NAME="Pattern found in HTTP Response"
      ISSUE_DETAIL="HTTP Response contains this pattern: " + PATTERN
      ISSUE_BACKGROUND="The web site has exposed sensitive information"
      REMEDIATION_BACKGROUND="Sensitive information"
      REMEDIATION_DETAIL="Ensure sensitive information is only shown to authorized users"
      SEVERITY="Information"
      CONFIDENCE="Certain"
      
      issue = list()
      match = self.getMatches(baseRequestResponse.getResponse(), PATTERN)
      if len(match) > 0:
        httpmsgs = [self._callbacks.applyMarkers(baseRequestResponse,None,match)]
        issue.append(ScanIssue(baseRequestResponse.getHttpService(), self._helpers.analyzeRequest(baseRequestResponse).getUrl(), httpmsgs, ISSUE_NAME, ISSUE_DETAIL, SEVERITY, CONFIDENCE, REMEDIATION_DETAIL, ISSUE_BACKGROUND, REMEDIATION_BACKGROUND))
      return issue


    def logScanIssue(self, baseRequestResponse):
      '''This is redundant (mostly) of the doPassiveScan function'''
      PATTERN="BEEFSESSION"
      ISSUE_NAME="Pattern found in Cookie header"
      ISSUE_DETAIL="HTTP Request contains this pattern: " + PATTERN
      ISSUE_BACKGROUND="The web browser might be hooked with BeEF"
      REMEDIATION_BACKGROUND="Potential XSS Zombie"
      REMEDIATION_DETAIL="Ensure this was from you"
      SEVERITY="High"
      CONFIDENCE="Tentative"
      for header in self._helpers.analyzeRequest(baseRequestResponse).getHeaders():
          if "Cookie:" in header and PATTERN in header:
            match = self.getMatches(baseRequestResponse.getRequest(), PATTERN)
            httpmsgs = [self._callbacks.applyMarkers(baseRequestResponse,match,None)]
            issue=ScanIssue(baseRequestResponse.getHttpService(), self._helpers.analyzeRequest(baseRequestResponse).getUrl(), httpmsgs, ISSUE_NAME, ISSUE_DETAIL, SEVERITY, CONFIDENCE, REMEDIATION_DETAIL, ISSUE_BACKGROUND, REMEDIATION_BACKGROUND)
            self._callbacks.addScanIssue(issue)
      return

    def doActiveScan(self, baseRequestResponse, insertionPoint):
      INJECTION="id"
      PATTERN="uid="
      ISSUE_NAME="Command Injection"
      ISSUE_DETAIL="Vulnerable to command injection"
      ISSUE_BACKGROUND="The web site has responded to command injection attempt"
      REMEDIATION_BACKGROUND="Sanitize all inputs"
      REMEDIATION_DETAIL="Assume all client supplied inputs are bad."
      SEVERITY="High"
      CONFIDENCE="Certain"
      issue = list()
      checkRequest = insertionPoint.buildRequest(INJECTION)
      checkRequestResponse = self._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), checkRequest)
      match = self.getMatches(checkRequestResponse.getResponse(), PATTERN)
      if len(match) > 0:
        requestHighlights = [insertionPoint.getPayloadOffsets(INJECTION)]
        httpmsgs = [self._callbacks.applyMarkers(checkRequestResponse, requestHighlights, match)]
        issue.append(ScanIssue(baseRequestResponse.getHttpService(), self._helpers.analyzeRequest(baseRequestResponse).getUrl(), httpmsgs,ISSUE_NAME, ISSUE_DETAIL, SEVERITY, CONFIDENCE, REMEDIATION_DETAIL, ISSUE_BACKGROUND, REMEDIATION_BACKGROUND))
      
      return issue
      

class ScanIssue(IScanIssue):
  '''This is our custom IScanIssue class implementation.'''
  def __init__(self, httpService, url, httpMessages, issueName, issueDetail, severity, confidence, remediationDetail, issueBackground, remediationBackground):
      self._issueName = issueName
      self._httpService = httpService
      self._url = url
      self._httpMessages = httpMessages
      self._issueDetail = issueDetail
      self._severity = severity
      self._confidence = confidence
      self._remediationDetail = remediationDetail
      self._issueBackground = issueBackground
      self._remediationBackground = remediationBackground


  def getConfidence(self):
      return self._confidence

  def getHttpMessages(self):
      return self._httpMessages
      #return None

  def getHttpService(self):
      return self._httpService

  def getIssueBackground(self):
      return self._issueBackground

  def getIssueDetail(self):
      return self._issueDetail

  def getIssueName(self):
      return self._issueName

  def getIssueType(self):
      return 0

  def getRemediationBackground(self):
      return self._remediationBackground

  def getRemediationDetail(self):
      return self._remediationDetail

  def getSeverity(self):
      return self._severity

  def getUrl(self):
      return self._url

  def getHost(self):
      return 'localhost'

  def getPort(self):
      return int(80)


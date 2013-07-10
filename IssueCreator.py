'''
Issue Creator
-by @luxcupitor

example burp python extension
-add a proxy or repeater item as a Scanner Issue

Useful if you've worked hard on an issue through Repeater and would like to add the
finished results to the Scanner tab to keep better track of it.
'''
from burp import IBurpExtender
from burp import IScanIssue
from burp import IScannerCheck
from burp import IScannerInsertionPoint
from burp import ITab
from burp import IContextMenuFactory
from java.io import PrintWriter;
from array import array
from java.awt import Component;
from java.awt import FlowLayout;
from java.awt import Panel, BorderLayout, Dimension, Font, GridLayout, Color
from java.awt.event import ActionEvent;
from java.awt.event import ActionListener;
from javax.swing import JButton, JMenuItem, JFrame, JLabel, BorderFactory, ButtonGroup, JPanel, JTextArea, JTextField, JComboBox, JRadioButton, JScrollPane, JSplitPane, JList, WindowConstants, SwingConstants

class BurpExtender(IBurpExtender, ITab, IScannerCheck, IScannerInsertionPoint, IContextMenuFactory):

    # definitions
    EXTENSION_NAME="IssueCreator"
    tmpl = dict()
    tmpl['XSS'] = dict()
    tmpl['XSS']['name'] = 'Cross-Site Scripting (reflected)'
    tmpl['XSS']['idetail'] = 'It is possible to inject arbitrary JavaScript into the application\'s response'
    tmpl['XSS']['ibackground'] = '''Reflected cross-site scripting vulnerabilities arise when data is copied from a request and echoed into the application's immediate response in an unsafe way. An attacker can use the vulnerability to construct a request which, if issued by another application user, will cause JavaScript code supplied by the attacker to execute within the user's browser in the context of that user's session with the application.  The attacker-supplied code can perform a wide variety of actions, such as stealing the victim's session token or login credentials, performing arbitrary actions on the victim's behalf, and logging their keystrokes.  Users can be induced to issue the attacker's crafted request in various ways. For example, the attacker can send a victim a link containing a malicious URL in an email or instant message. They can submit the link to popular web sites that allow content authoring, for example in blog comments. And they can create an innocuous looking web site which causes anyone viewing it to make arbitrary cross-domain requests to the vulnerable application (using either the GET or the POST method).  The security impact of cross-site scripting vulnerabilities is dependent upon the nature of the vulnerable application, the kinds of data and functionality which it contains, and the other applications which belong to the same domain and organization. If the application is used only to display non-sensitive public content, with no authentication or access control functionality, then a cross-site scripting flaw may be considered low risk. However, if the same application resides on a domain which can access cookies for other more security-critical applications, then the vulnerability could be used to attack those other applications, and so may be considered high risk. Similarly, if the organization which owns the application is a likely target for phishing attacks, then the vulnerability could be leveraged to lend credibility to such attacks, by injecting Trojan functionality into the vulnerable application, and exploiting users' trust in the organization in order to capture credentials for other applications which it owns. In many kinds of application, such as those providing online banking functionality, cross-site scripting should always be considered high risk. '''
    tmpl['XSS']['rdetail'] = ''''Input should be validated as strictly as possible on arrival, given the kind of content which it is expected to contain. For example, personal names should consist of alphabetical and a small range of typographical characters, and be relatively short; a year of birth should consist of exactly four numerals; email addresses should match a well-defined regular expression. Input which fails the validation should be rejected, not sanitized.
    User input should be HTML-encoded at any point where it is copied into application responses. All HTML metacharacters, including < > " ' and =, should be replaced with the corresponding HTML entities (&lt; &gt; etc).
    In cases where the application's functionality allows users to author content using a restricted subset of HTML tags and attributes (for example, blog comments which allow limited formatting and linking), it is necessary to parse the supplied HTML to validate that it does not use any dangerous syntax; this is a non-trivial task.
    '''
    tmpl['XSS']['rbackground'] = 'do not trust user input!'

    tmpl['SQLi'] = dict()
    tmpl['SQLi']['name'] = 'SQL Injection'
    tmpl['SQLi']['idetail'] = 'Input parameter appears to be vulnerable to SQL injection attacks.'
    tmpl['SQLi']['ibackground'] = '''SQL injection vulnerabilities arise when user-controllable data is incorporated into database SQL queries in an unsafe manner. An attacker can supply crafted input to break out of the data context in which their input appears and interfere with the structure of the surrounding query.
    Various attacks can be delivered via SQL injection, including reading or modifying critical application data, interfering with application logic, escalating privileges within the database and executing operating system commands.
    '''
    tmpl['SQLi']['rdetail'] = '''The most effective way to prevent SQL injection attacks is to use parameterized queries (also known as prepared statements) for all database access. This method uses two steps to incorporate potentially tainted data into SQL queries: first, the application specifies the structure of the query, leaving placeholders for each item of user input; second, the application specifies the contents of each placeholder. Because the structure of the query has already defined in the first step, it is not possible for malformed data in the second step to interfere with the query structure. You should review the documentation for your database and application platform to determine the appropriate APIs which you can use to perform parameterized queries. It is strongly recommended that you parameterize every variable data item that is incorporated into database queries, even if it is not obviously tainted, to prevent oversights occurring and avoid vulnerabilities being introduced by changes elsewhere within the code base of the application.
    
    '''
    tmpl['SQLi']['rbackground'] = 'SQL Injection background'

    tmpl['Insecure-Cookie'] = dict()
    tmpl['Insecure-Cookie']['name'] = 'Cookie Was Set Without Secure Flag'
    tmpl['Insecure-Cookie']['idetail'] = 'Application has set a secure cookie without the secure attribute'
    tmpl['Insecure-Cookie']['ibackground'] = 'Client will send this cookie over the clear via http.  This could be eavesdropped on.'
    tmpl['Insecure-Cookie']['rdetail'] = 'The application should set all cookies that are session related or sensitive in nature with the secure attribute.'
    tmpl['Insecure-Cookie']['rbackground'] = '...'

    tmpl['Your-Item'] = dict()
    tmpl['Your-Item']['name'] = 'My issue name'
    tmpl['Your-Item']['idetail'] = 'My issue detail'
    tmpl['Your-Item']['ibackground'] = 'the issue background here'
    tmpl['Your-Item']['rdetail'] = '''the remediation detail.  i'll put this in triple quotes. because.
    '''
    tmpl['Your-Item']['rbackground'] = 'this is remediation background information for my issue'
    
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
        self._stdout.println('TIP: right click on items in proxy or repeater tab')
        self._stdout.println('and select "Add as Issue to Scanner".')
        self._stdout.println('')
        # set our extension name
        callbacks.setExtensionName(self.EXTENSION_NAME)
        
        # setup a context menu for the proxy tab. needs createMenuItems
        callbacks.registerContextMenuFactory(self)

        return

    def createMenuItems(self, caller):
      '''caller is the burpsuite context that invoked the menu'''
      menu = []
      #Proxy tab is context 6/repeater request is 0/repeater response is 3
      idx = caller.getInvocationContext()
      if idx == 6 or idx == 0 or idx == 3:
        menu.append(JMenuItem("Add as Issue to Scanner", None, actionPerformed=lambda x, c=caller: self.launchGui(c)))
      return menu if menu else None

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

    def logScanIssue(self, baseRequestResponse):
      '''This is redundant (mostly) of the doPassiveScan function'''
      reqPATTERN=self.reqPattern.text
      resPATTERN=self.resPattern.text
      ISSUE_NAME=self.issueNameField.text
      ISSUE_DETAIL=self.issueDetailField.text
      ISSUE_BACKGROUND=self.issueBackgroundField.text
      REMEDIATION_BACKGROUND=self.remediationBackgroundField.text
      REMEDIATION_DETAIL=self.remediationDetailField.text
      if self.radioBtnSevHigh.isSelected():
        SEVERITY="High"
      elif self.radioBtnSevMedium.isSelected():
        SEVERITY="Medium"
      else:
        SEVERITY="Low"
      CONFIDENCE="Certain"
      self._stdout = PrintWriter(self._callbacks.getStdout(), True)
      self._stdout.println('logScanIssue has been called')
      self._stdout.println('[-] ISSUE_NAME: ' + ISSUE_NAME)
      self._stdout.println('[-] ISSUE_DETAIL: ' + ISSUE_DETAIL)
      self._stdout.println('[-] ISSUE_BACKGROUND: ' + ISSUE_BACKGROUND)
      self._stdout.println('[-] REMEDIATION_DETAIL: ' + REMEDIATION_DETAIL)
      self._stdout.println('[-] REMEDIATION_BACKGROUND: ' + REMEDIATION_BACKGROUND)
      self._stdout.println('[-] SEVERITY: ' + SEVERITY)
      self._stdout.println('[-] CONFIDENCE: ' + CONFIDENCE)
      match = False
      if reqPATTERN == "":
        reqmatch = None
      else:
        reqmatch = self.getMatches(baseRequestResponse.getRequest(), reqPATTERN)
        match = True
      if resPATTERN == "":
        resmatch = None
      else:
        resmatch = self.getMatches(baseRequestResponse.getResponse(), resPATTERN)
        match = True
      if match:
        httpmsgs = [self._callbacks.applyMarkers(baseRequestResponse,reqmatch,resmatch)]
        issue=ScanIssue(baseRequestResponse.getHttpService(), self._helpers.analyzeRequest(baseRequestResponse).getUrl(), httpmsgs, ISSUE_NAME, ISSUE_DETAIL, SEVERITY, CONFIDENCE, ISSUE_BACKGROUND, REMEDIATION_DETAIL, REMEDIATION_BACKGROUND)
        self._callbacks.addScanIssue(issue)
        self.closeUI(None)

      return

    def launchGui(self, caller):
      self._stdout = PrintWriter(self._callbacks.getStdout(), True)
      self._stdout.println('Launching gui')
      callMessage = caller.getSelectedMessages()
      self.msg1 = callMessage[0]

      #setup frame
      self.frame = JFrame('Create Issue', windowClosing=self.closeUI)
      Border = BorderFactory.createLineBorder(Color.BLACK)

      #create split panel to add issue panel and template panel
      self.splitPane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
      self.frame.add(self.splitPane)

      #panel setup and add to splitPane
      self.issuePanel = JPanel(GridLayout(0,2))
      self.splitPane.setLeftComponent(self.issuePanel)

      #setup issue name text fields to add to panel
      self.issueNameField = JTextField('',15)
      self.issueNameLabel = JLabel("IssueName:", SwingConstants.CENTER)
      self.issuePanel.add(self.issueNameLabel)
      self.issuePanel.add(self.issueNameField)

      #add issue detail text area
      self.issueDetailField = JTextArea()
      self.issueDetailField.editable = True
      self.issueDetailField.wrapStyleWord = True
      self.issueDetailField.lineWrap = True
      self.issueDetailField.alignmentX = Component.LEFT_ALIGNMENT
      self.issueDetailField.size = (200, 20)
      self.issueDetailField.setBorder(Border)
      self.idfSp = JScrollPane()
      self.idfSp.getViewport().setView((self.issueDetailField))
      self.issuePanel.add(JLabel("Issue Detail:", SwingConstants.CENTER))
      self.issuePanel.add(self.idfSp)

      self.issueBackgroundField= JTextArea()
      self.issueBackgroundField.editable = True
      self.issueBackgroundField.wrapStyleWord = True
      self.issueBackgroundField.lineWrap = True
      self.issueBackgroundField.alignmentX = Component.LEFT_ALIGNMENT
      self.issueBackgroundField.size = (200, 20)
      self.issueBackgroundField.setBorder(Border)
      self.ibfSp = JScrollPane()
      self.ibfSp.getViewport().setView((self.issueBackgroundField))
      self.issuePanel.add(JLabel("Issue Background:", SwingConstants.CENTER))
      self.issuePanel.add(self.ibfSp)

      #add remediation detail text area
      self.remediationDetailField = JTextArea()
      self.remediationDetailField.editable = True
      self.remediationDetailField.wrapStyleWord = True
      self.remediationDetailField.lineWrap = True
      self.remediationDetailField.alignmentX = Component.LEFT_ALIGNMENT
      self.remediationDetailField.size = (200, 20)
      self.remediationDetailField.setBorder(Border)
      self.rdfSp = JScrollPane()
      self.rdfSp.getViewport().setView((self.remediationDetailField))
      self.issuePanel.add(JLabel("Remediation Detail:", SwingConstants.CENTER))
      self.issuePanel.add(self.rdfSp)

      self.remediationBackgroundField= JTextArea()
      self.remediationBackgroundField.editable = True
      self.remediationBackgroundField.wrapStyleWord = True
      self.remediationBackgroundField.lineWrap = True
      self.remediationBackgroundField.alignmentX = Component.LEFT_ALIGNMENT
      self.remediationBackgroundField.size = (200, 20)
      self.remediationBackgroundField.setBorder(Border)
      self.rbfSp = JScrollPane()
      self.rbfSp.getViewport().setView((self.remediationBackgroundField))
      self.issuePanel.add(JLabel("Remediation Background:", SwingConstants.CENTER))
      self.issuePanel.add(self.rbfSp)

      #add radio buttons for severity
      self.radioBtnSevHigh = JRadioButton('High', actionPerformed=None)
      self.radioBtnSevMedium = JRadioButton('Medium', actionPerformed=None)
      self.radioBtnSevLow = JRadioButton('Low', actionPerformed=None)
      severityButtonGroup = ButtonGroup()
      severityButtonGroup.add(self.radioBtnSevHigh)
      severityButtonGroup.add(self.radioBtnSevMedium)
      severityButtonGroup.add(self.radioBtnSevLow)
      self.radioBtnSevHigh.setSelected(True)
      self.issuePanel.add(JLabel("Severity:", SwingConstants.CENTER))
      self.issuePanel.add(self.radioBtnSevHigh)
      self.issuePanel.add(self.radioBtnSevMedium)
      self.issuePanel.add(self.radioBtnSevLow)
    
      self.reqPattern = JTextField('',15)
      self.issuePanel.add(JLabel("Mark Pattern in Request:", SwingConstants.CENTER))
      self.issuePanel.add(self.reqPattern)
      self.resPattern = JTextField('',15)
      self.issuePanel.add(JLabel("Mark Pattern in Response:", SwingConstants.CENTER))
      self.issuePanel.add(self.resPattern)

      #add a button
      self.issueButton = JButton('Add!', actionPerformed=lambda x, m=self.msg1: self.logScanIssue(m))
      self.issuePanel.add(self.issueButton)

      #template panel setup
      self.templatePanel = JPanel(GridLayout(1,2))
      self.splitPane.setRightComponent(self.templatePanel)
    
      #add a list of templates
      self.templatePanel.add(JLabel("Select from Templates", SwingConstants.CENTER))
      self.templateData = tuple(self.tmpl.keys())
      self.templateList = JList(self.templateData)
      self.templateScrollPane = JScrollPane()

      #self.templateScrollPane.setPreferredSize(Dimension(100,125))
      self.templateScrollPane.getViewport().setView((self.templateList))
      self.templatePanel.add(self.templateScrollPane)
      self.templateButton = JButton('Apply', actionPerformed=self.applyTemplate)
      self.templatePanel.add(self.templateButton)
     
      #pack up the frame and display it
      self.frame.pack()
      self.show()
     
    def applyTemplate(self, event):
      selected = self.templateList.selectedIndex
      if selected >= 0:
        self.issueNameField.text = self.tmpl[self.templateData[selected]]['name']
        self.issueDetailField.text = self.tmpl[self.templateData[selected]]['idetail']
        self.issueBackgroundField.text = self.tmpl[self.templateData[selected]]['ibackground']
        self.remediationDetailField.text = self.tmpl[self.templateData[selected]]['rdetail']
        self.remediationBackgroundField.text = self.tmpl[self.templateData[selected]]['rbackground']

    def show(self):
      self.frame.visible = True


    def closeUI(self, event):
        self.frame.setVisible(False)
        self.frame.dispose()
   

class ScanIssue(IScanIssue):
  '''This is our custom IScanIssue class implementation.'''
  def __init__(self, httpService, url, httpMessages, issueName, issueDetail, severity, confidence, issueBackground, remediationDetail, remediationBackground):
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


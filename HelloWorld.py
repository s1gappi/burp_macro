from burp import (IBurpExtender, IMessageEditorTab, IMessageEditorTabFactory,
                    IHttpListener, IProxyListener, ITab, IMessageEditorController)
from java.io import PrintWriter
from java.lang import RuntimeException
from java.util import ArrayList
from java.awt import Component;
from java.io import PrintWriter;
from java.util import ArrayList;
from java.util import List;
from javax.swing import JScrollPane;
from javax.swing import JSplitPane;
from javax.swing import JLabel;
from javax.swing import JPanel;
from javax.swing import JTabbedPane;
from javax.swing import JTable;
from javax.swing import SwingUtilities;
from javax.swing.table import AbstractTableModel;
from threading import Lock

class BurpExtender(IBurpExtender, 
                    IMessageEditorTabFactory, 
                    IHttpListener,
                    IProxyListener,
                    ITab,
                    IMessageEditorController,
                    AbstractTableModel):
    

    #
    # implement IBurpExtender
    #    
    def	registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        # set our extension name
        callbacks.setExtensionName("Tutorial Functions (my)")
        
        # obtain our output and error streams
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)
        
        # write a message to our output stream
        self._stdout.println("Hello output222")
        
        # write a message to our error stream
        #stderr.println("Hello errors111")
        
        # write a message to the Burp alerts tab
        #callbacks.issueAlert("Hello alerts")
        
        # throw an exception that will appear in our error stream
        # raise RuntimeException("Hello exception")

        
        # 
        # *** [ EventLisetr ] 
        # --------------------
        # HttpListener & ProxyListener can get "Request & Response body"
        # callbacks.registerHttpListener(self)
        # callbacks.registerProxyListener(self)
        # --------------------



        # 
        # *** [ MessageEditorTab ]
        # --------------------        
        # register ourselves as a message editor tab factory
        # Proxy -> Request -> Tab
        callbacks.registerMessageEditorTabFactory(self)
        # --------------------
                
        
                
        # 
        # *** [ addSuiteTab ]
        # --------------------
        # create the log and a lock on which to synchronize when adding log entries
        self._log = ArrayList()
        self._lock = Lock()
        
        # main split pane
        # self._splitpane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        self._split_three_pane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        
        # toppane = JPanel()
        # toppane.add(JLabel('top'))
        
        bottom_splitpane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        
        leftpane = JPanel()
        leftpane.add(JLabel('bottom left'))
        rightpane = JPanel()
        rightpane.add(JLabel('bottom right'))
        
        bottom_splitpane.setLeftComponent(leftpane)
        bottom_splitpane.setRightComponent(rightpane)
        
        # self._split_three_pane.setTopComponent(toppane)
        self._split_three_pane.setBottomComponent(bottom_splitpane)
        
        
        # table of log entries -> Top Panel
        logTable = Table(self)
        scrollPane = JScrollPane(logTable)
        self._split_three_pane.setTopComponent(scrollPane)

        # tabs with request viewers  -> Bottom-Left Panel
        tabs_left = JTabbedPane()
        self._requestViewer = callbacks.createMessageEditor(self, False)
        tabs_left.addTab("Request1", self._requestViewer.getComponent())
        bottom_splitpane.setLeftComponent(tabs_left)

        # tabs with response viewers  -> Bottom-Right Panel
        tabs_right = JTabbedPane()
        self._responseViewer = callbacks.createMessageEditor(self, False)
        tabs_right.addTab("Response2", self._responseViewer.getComponent())
        bottom_splitpane.setRightComponent(tabs_right)
        
        self._split_three_pane.setBottomComponent(bottom_splitpane)
        
        
        # customize our UI components
        # callbacks.customizeUiComponent(self._splitpane)
        # callbacks.customizeUiComponent(logTable)
        # callbacks.customizeUiComponent(scrollPane)
        # callbacks.customizeUiComponent(tabs)
        
        # add the custom tab to Burp's UI
        callbacks.addSuiteTab(self)
        
        # register ourselves as an HTTP listener
        # callbacks.registerHttpListener(self)
        # --------------------


    # 
    # ***[EventLisetr] 
    # -----------------------------
    #
    # implement IHttpListener
    #
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # _tmp = ''
        # _tmp += messageInfo.getHttpService().toString() + " [" + self._callbacks.getToolName(toolFlag) + "]"
        # self._stdout.println(_tmp)
        
        if messageIsRequest:
            # (Proxy) When Request
            _tmp = "(HttpListener)Proxy request to "
            
            path = str(self._helpers.analyzeRequest(messageInfo.getRequest()).getHeaders()[0].split()[1])
            val = messageInfo.getHttpService().getProtocol() + "://" \
                    + messageInfo.getHttpService().getHost() + ":"   \
                    + str(messageInfo.getHttpService().getPort()) + path
                    
            request = self._helpers.bytesToString(messageInfo.getRequest())
            result = messageInfo
            path_params = str(self._helpers.analyzeRequest(result.getRequest()).getHeaders()[0].split()[1])
            # params = self._helpers.analyzeRequest(result.getRequest()).getParameters()


            self._stdout.println(request)
            self._stdout.println("[path_params]:" + path_params)
            
        else:
            # (Proxy) When Response
            _tmp = "(HttpLister)Proxy response from "
            
            response = self._helpers.bytesToString(messageInfo.getResponse())
                        
            self._stdout.println(_tmp)
            self._stdout.println(response)
            # self._stdout.println(message.getMessageInfo().getResponse())


    #
    # implement IProxyListener
    #
    def processProxyMessage(self, messageIsRequest, message):
        if messageIsRequest:
            # (Proxy) When Request
            _tmp = "(ProxyListener)Proxy request to "
            
            path = str(self._helpers.analyzeRequest(message.getMessageInfo().getRequest()).getHeaders()[0].split()[1])
            val = message.getMessageInfo().getHttpService().getProtocol() + "://" \
                    + message.getMessageInfo().getHttpService().getHost() + ":"   \
                    + str(message.getMessageInfo().getHttpService().getPort()) + path
                    
            request = self._helpers.bytesToString(message.getMessageInfo().getRequest())
            result = message.getMessageInfo()
            path_params = str(self._helpers.analyzeRequest(result.getRequest()).getHeaders()[0].split()[1])
            # params = self._helpers.analyzeRequest(result.getRequest()).getParameters()


            self._stdout.println(request)
            self._stdout.println("[path_params]:" + path_params)
            
        else:
            # (Proxy) When Response
            _tmp = "(ProxyListener)Proxy response from "

            result = message.getMessageInfo()
            response = self._helpers.bytesToString(message.getMessageInfo().getResponse())
                        
            self._stdout.println(_tmp)
            self._stdout.println(response)
            # self._stdout.println(message.getMessageInfo().getResponse())


    # 
    # -----------------------
    # 



    # 
    # *** [ addSuiteTab ]
    # ----------------------------
    #
    # implement ITab
    #
    def getTabCaption(self):
        return "MyLogger"

    def getUiComponent(self):
        # return self._splitpane
        return self._split_three_pane
        
    #
    # implement IHttpListener
    #    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # only process requests
        if messageIsRequest:
            return
        
        # create a new log entry with the message details
        self._lock.acquire()
        row = self._log.size()
        self._log.add(LogEntry(toolFlag, self._callbacks.saveBuffersToTempFiles(messageInfo), self._helpers.analyzeRequest(messageInfo).getUrl()))
        self.fireTableRowsInserted(row, row)
        self._lock.release()

    #
    # extend AbstractTableModel
    #
    def getRowCount(self):
        try:
            return self._log.size()
        except:
            return 0

    def getColumnCount(self):
        return 2

    def getColumnName(self, columnIndex):
        if columnIndex == 0:
            return "Tool"
        if columnIndex == 1:
            return "URL"
        return ""

    def getValueAt(self, rowIndex, columnIndex):
        logEntry = self._log.get(rowIndex)
        if columnIndex == 0:
            return self._callbacks.getToolName(logEntry._tool)
        if columnIndex == 1:
            return logEntry._url.toString()
        return ""

    #
    # implement IMessageEditorController
    # this allows our request/response viewers to obtain details about the messages being displayed
    #
    def getHttpService(self):
        return self._currentlyDisplayedItem.getHttpService()

    def getRequest(self):
        return self._currentlyDisplayedItem.getRequest()

    def getResponse(self):
        return self._currentlyDisplayedItem.getResponse()

    # 
    # ----------------------------
    # 



    # 
    # *** [MessageEditorTab]
    # ----------------------------
    #
    # Create tab
    # 
    def createNewInstance(self, controller, editable):
        return MyTab(self, controller, editable)
    
    
class MyTab(IMessageEditorTab):
    def __init__(self, extender, controller, editable):
        self._extender = extender
        self._editable = editable

        # create an instance of Burp's text editor
        self._txtInput = extender._callbacks.createTextEditor()
        self._txtInput.setEditable(editable)
        
        
    # 
    # implement IMessageEditorTab
    # 
    
    def getTabCaption(self):
        return "mytab captions"
    
    def getUiComponent(self):
        return self._txtInput.getComponent()
    
    def isEnabled(self, content, isRequest):
        # What Conditions enable this tab.
        # ex) enable this tab for requests containg a data parameter.
        
        # [memo] If parameter"data" in Requset, 
        return True # isRequest \
        #     not self._extender._helpers.getRequestParameter(content, "data") is None
            
            
    def setMessage(self, content, isRequest):
        # "content" == Request Header, Body
        if content is None:
            # clear our display
            self._txtInput.setText(None)
            self._txtInput.setEditable(False)
            
        else:
            # Get parameter from "content(Request)"
            # parameter = self._extender._helpers.getRequestParameter(content, "data")
            
            self._txtInput.setText("set Message here")
            self._txtInput.setEditable(self._editable)
            # self._txtInput.setEditable(True)
            
        # remember the displayed content
        # XXX: Unknown 7/5
        # self._currentMessage = content + 'add from set Messesage'


    #
    # ----------------------------
    #
    

    
# 
# *** [ addSuiteTab ]
# ----------------------------
#
# extend JTable to handle cell selection
#
class Table(JTable):
    def __init__(self, extender):
        self._extender = extender
        self.setModel(extender)
    
    def changeSelection(self, row, col, toggle, extend):
    
        # show the log entry for the selected row
        # I see! 7/5(Tue)
        # ~~_requestViewer.setMessage(display_content, parameters tab on/off)
        logEntry = self._extender._log.get(row)
        self._extender._requestViewer.setMessage(logEntry._requestResponse.getRequest(), True)
        self._extender._responseViewer.setMessage(logEntry._requestResponse.getResponse(), False)
        self._extender._currentlyDisplayedItem = logEntry._requestResponse
        
        JTable.changeSelection(self, row, col, toggle, extend)
    
#
# class to hold details of each log entry
#
class LogEntry:
    def __init__(self, tool, requestResponse, url):
        self._tool = tool
        self._requestResponse = requestResponse
        self._url = url
        
#
# ----------------------------
#

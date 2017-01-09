package burp;

import java.awt.Component;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.net.URLDecoder;
import javax.swing.ListSelectionModel;
import java.io.UnsupportedEncodingException;
import javax.swing.JSeparator;
import java.awt.datatransfer.*;
import java.awt.Toolkit;

public class BurpExtender extends AbstractTableModel implements IBurpExtender, ITab, IHttpListener, IMessageEditorController
{
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private JSplitPane splitPane;
    private JSplitPane splitPane2;
    private IMessageEditor requestViewer;
    private IMessageEditor responseViewer;
    private ParametersTable parametersTable;
    private final List<ReflectedEntry> reflectedEntryList = new ArrayList<>();
    private IHttpRequestResponse currentlyDisplayedItem;
    private PrintWriter stdout;
    
    // Right click menu elements
    private JMenuItem menuItemScannerAll;
    private JMenuItem menuItemScannerParameters;
    private JMenuItem menuItemIntruder;
    private JMenuItem menuItemRepeater;
    private JMenuItem menuItemCopyURL;
    private JMenuItem menuItemDeleteItem;
    private JMenuItem menuItemClearList;

    

    //
    // implement IBurpExtender
    //
    
    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
    {
        // keep a reference to our callbacks object
        this.callbacks = callbacks;
        
        // obtain an extension helpers object
        helpers = callbacks.getHelpers();
        
        // set our extension name
        callbacks.setExtensionName("Reflection v0.26");
        
        // obtain our output and error streams
        stdout = new PrintWriter(callbacks.getStdout(), true);
        
        // create our UI
        SwingUtilities.invokeLater(new Runnable() 
        {
            @Override
            public void run()
            {
                // Main split pane
                splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
                splitPane.setResizeWeight(0.4f);
                splitPane2 = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
                splitPane2.setResizeWeight(0.35f);
                
                // Table of reflected entries
                ReflectedTable requestTable = new ReflectedTable(BurpExtender.this);
                ParametersTableModel parametersTableModel = new ParametersTableModel();
                
                parametersTable = new ParametersTable(parametersTableModel);
                parametersTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
                
                
                // Setting the colums width
                requestTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
                requestTable.getColumnModel().getColumn(0).setPreferredWidth(30);
                requestTable.getColumnModel().getColumn(1).setPreferredWidth(300);
                requestTable.getColumnModel().getColumn(2).setPreferredWidth(80);
                requestTable.getColumnModel().getColumn(3).setPreferredWidth(500);
                requestTable.getColumnModel().getColumn(4).setPreferredWidth(80);
                requestTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
                
                
                
                // Creating popup menu
                JPopupMenu popupMenu = new JPopupMenu();
                menuItemScannerAll = new JMenuItem("Active scan whole request");
                menuItemScannerParameters = new JMenuItem("Active scan reflected parameters");
                menuItemIntruder = new JMenuItem("Send request to Intruder");
                menuItemRepeater = new JMenuItem("Send request to Repeater");
                menuItemCopyURL = new JMenuItem("Copy URL");
                menuItemDeleteItem = new JMenuItem("Delete item");
                menuItemClearList = new JMenuItem("Clear list");
                
               
                menuItemScannerAll.addActionListener(requestTable);
                menuItemScannerParameters.addActionListener(requestTable);
                menuItemIntruder.addActionListener(requestTable);
                menuItemRepeater.addActionListener(requestTable);
                menuItemCopyURL.addActionListener(requestTable);
                menuItemDeleteItem.addActionListener(requestTable);
                menuItemClearList.addActionListener(requestTable);
                
                popupMenu.add(menuItemScannerAll);
                popupMenu.add(menuItemScannerParameters);
                popupMenu.add(menuItemIntruder);
                popupMenu.add(menuItemRepeater);
                popupMenu.add(new JSeparator());
                popupMenu.add(menuItemCopyURL);
                popupMenu.add(menuItemDeleteItem);
                popupMenu.add(new JSeparator());
                popupMenu.add(menuItemClearList);
                
                requestTable.setComponentPopupMenu(popupMenu);
                
                JScrollPane scrollPane = new JScrollPane(requestTable);
                JScrollPane scrollPane2 = new JScrollPane(parametersTable);
                
                splitPane.setLeftComponent(scrollPane);
                splitPane2.setLeftComponent(scrollPane2);
                
                // Tabs with request/response viewers
                JTabbedPane tabs = new JTabbedPane();
                requestViewer = callbacks.createMessageEditor(BurpExtender.this, false);
                responseViewer = callbacks.createMessageEditor(BurpExtender.this, false);
                tabs.addTab("Request", requestViewer.getComponent());
                tabs.addTab("Response", responseViewer.getComponent());
                
                splitPane.setRightComponent(splitPane2);
                splitPane2.setRightComponent(tabs);
                splitPane.setDividerLocation(0.5);
                splitPane2.setDividerLocation(0.3);

                // Customize our UI components
                callbacks.customizeUiComponent(splitPane);
                callbacks.customizeUiComponent(splitPane2);
                callbacks.customizeUiComponent(requestTable);
                callbacks.customizeUiComponent(parametersTable);
                callbacks.customizeUiComponent(scrollPane);
                callbacks.customizeUiComponent(scrollPane2);
                callbacks.customizeUiComponent(tabs);
                
                
                // add the custom tab to Burp's UI
                callbacks.addSuiteTab(BurpExtender.this);
                
                // register ourselves as an HTTP listener
                callbacks.registerHttpListener(BurpExtender.this); 
                
                stdout.println("Reflection plugin v0.26");
                stdout.println("Author: Marek Zmyslowski");
                stdout.println("Email: marekzmyslowski@poczta.onet.pl");
            }
        });

    }

    //
    // implement ITab
    //

    @Override
    public String getTabCaption()
    {
        return "Reflection";
    }

    @Override
    public Component getUiComponent()
    {
        return splitPane;
    }

    //
    // implement IHttpListener
    //
    
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo)
    {
        // Process only responses from Proxy or Spider tool
        if (!messageIsRequest && (toolFlag == IBurpExtenderCallbacks.TOOL_SPIDER || toolFlag == IBurpExtenderCallbacks.TOOL_PROXY))
        {
            if (callbacks.isInScope(helpers.analyzeRequest(messageInfo).getUrl()))
            {
                IHttpRequestResponseWithMarkers messageInfoMarked = callbacks.applyMarkers(messageInfo, null, null);
                List<IParameter> params = helpers.analyzeRequest(messageInfo).getParameters();
                String response = new String(messageInfo.getResponse());
                boolean foundReflection;
                int lastpos;
                List<int[]> requestMarkers = new ArrayList<>();
                List<int[]> responseMarkers = new ArrayList<>();
                List<String[]> parameters = new ArrayList<>();
                String reflectedValues;
                String paramValueDecoded = "";
                
                for (IParameter param: params)
                {
                    if (helpers.getRequestParameter(messageInfo.getRequest(), param.getName()).getType() == 2)
                    {
                        continue;
                    }
                    reflectedValues = "";
                    if ((param.getValue().length() >= 4))
                    {
                        foundReflection = false;
                        lastpos = 0;
                        while (response.indexOf(param.getValue(), lastpos) != -1)
                        {
                            foundReflection = true;
                            lastpos = response.indexOf(param.getValue(), lastpos);
                            
                            // Marking value in the response
                            responseMarkers.add(new int[] {lastpos,lastpos + param.getValue().length()});
                            lastpos += 1;

                        }
                        if (foundReflection)
                            reflectedValues = param.getValue();
                        foundReflection = false;
                        try
                        {
                            if (!param.getValue().equals(URLDecoder.decode(param.getValue(), "UTF-8")))
                            {
                                paramValueDecoded = URLDecoder.decode(param.getValue(), "UTF-8");
                                while (response.indexOf(paramValueDecoded, lastpos) != -1)
                                {
                                    foundReflection = true;
                                    lastpos = response.indexOf(paramValueDecoded, lastpos);
                            
                                    // Marking value in the response
                                    responseMarkers.add(new int[] {lastpos,lastpos + paramValueDecoded.length()});
                                    lastpos += 1;
                                }
                            }
                            if (foundReflection)
                            {
                                if (reflectedValues.equals(""))
                                    reflectedValues = paramValueDecoded;
                                else
                                   reflectedValues = " , " + reflectedValues;
                            }    
                        }catch(UnsupportedEncodingException e){
                            stdout.println(e); 
                        }
                        
                        if (!reflectedValues.equals(""))
                        {
                            // Marking param value in the request
                            requestMarkers.add(new int[] {param.getValueStart(),param.getValueEnd()});
                            messageInfoMarked = callbacks.applyMarkers(messageInfo, requestMarkers, responseMarkers);
                            parameters.add(new String[]{param.getName(), param.getValue(), reflectedValues});
                        }
                    }
          
                }
                // create a new log entry with the message details
                if (parameters.size() > 0)
                {
                    synchronized(reflectedEntryList)
                    {
                        int row = reflectedEntryList.size();
                        reflectedEntryList.add(new ReflectedEntry(messageInfoMarked, helpers.analyzeRequest(messageInfo).getUrl(), 
                                helpers.analyzeRequest(messageInfo).getMethod(), parameters, callbacks.getToolName(toolFlag)));
                        fireTableRowsInserted(row, row);
                    }
                }
            }
        }
    }

    //
    // extend AbstractTableModel
    //
    
    @Override
    public int getRowCount()
    {
        return reflectedEntryList.size();
    }

    @Override
    public int getColumnCount()
    {
        return 5;
    }

    @Override
    public String getColumnName(int columnIndex)
    {
        switch (columnIndex)
        {
            case 0:
                return "#";
            case 1:
                return "Host";
            case 2:
                return "Method";
            case 3:
                return "URL";
            case 4:
                return "Tool";
            default:
                return "";
        }
    }

    @Override
    public Class<?> getColumnClass(int columnIndex)
    {
        return String.class;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex)
    {
        ReflectedEntry reflectedEntry = reflectedEntryList.get(rowIndex);

        switch (columnIndex)
        {
            case 0:
                return Integer.toString(rowIndex+1);
            case 1:
                return (reflectedEntry.url.getProtocol() + "://" + reflectedEntry.url.getHost());
            case 2:
                return reflectedEntry.method;
            case 3:
                return reflectedEntry.url.getFile();
            case 4:
                return reflectedEntry.tool;
            default:
                return "";
        }
    }

    //
    // implement IMessageEditorController
    // this allows our request/response viewers to obtain details about the messages being displayed
    //
    
    @Override
    public byte[] getRequest()
    {
        return currentlyDisplayedItem.getRequest();
    }

    @Override
    public byte[] getResponse()
    {
        return currentlyDisplayedItem.getResponse();
    }

    @Override
    public IHttpService getHttpService()
    {
        return currentlyDisplayedItem.getHttpService();
    }

    
    //
    // Extend JTable to handle cell selection
    //
    
    private class ReflectedTable extends JTable implements ActionListener
    {
        public ReflectedTable(TableModel tableModel)
        {
            super(tableModel);
        }
        
        @Override
        public void actionPerformed(ActionEvent event) 
        {
            JMenuItem menu = (JMenuItem) event.getSource();
            int row = this.getSelectedRow();

            // If no row is selected
            if (row == -1)
                return;
            ReflectedEntry reflectedEntry = reflectedEntryList.get(row);
            boolean useHttps = false;
            if (reflectedEntry.url.getProtocol().toLowerCase().equals("https"))
                useHttps = true;
            if (menu == menuItemScannerAll) 
            {
                // Send the request to the Scanner
                callbacks.doActiveScan(reflectedEntry.url.getHost(), reflectedEntry.url.getPort(), useHttps, reflectedEntry.requestResponse.getRequest());
            } 
            else if (menu == menuItemScannerParameters)
            {
                // Send the reflected parameters to the Scanner
                callbacks.doActiveScan(reflectedEntry.url.getHost(), reflectedEntry.url.getPort(), useHttps, reflectedEntry.requestResponse.getRequest(), reflectedEntry.requestResponse.getRequestMarkers());
               
            }
            else if (menu == menuItemIntruder) 
            {
                // Send the request to the Intruder
                callbacks.sendToIntruder(reflectedEntry.url.getHost(), reflectedEntry.url.getPort(), useHttps,
                        reflectedEntry.requestResponse.getRequest(), reflectedEntry.requestResponse.getRequestMarkers());
            } 
            else if (menu == menuItemRepeater) 
            {
                // Send the request to the Repeater
                callbacks.sendToRepeater(reflectedEntry.url.getHost(), reflectedEntry.url.getPort(), useHttps, reflectedEntry.requestResponse.getRequest(),null);
            }   
            else if (menu == menuItemCopyURL)
            {
                // Copy URL to the clipboard
                StringSelection stringSelection = new StringSelection (reflectedEntry.url.toString());
                Clipboard clpbrd = Toolkit.getDefaultToolkit ().getSystemClipboard ();
                clpbrd.setContents (stringSelection, null);
            }
            else if (menu == menuItemDeleteItem)
            {
                reflectedEntryList.remove(row);
                
                //Reload the request table
                ((AbstractTableModel)this.getModel()).fireTableDataChanged();
                
                // Clear the parameters table
                ((ParametersTableModel)parametersTable.getModel()).reloadValues(new ReflectedEntry());
                
                // Clear request/response 
                requestViewer.setMessage(new byte[0], true);
                responseViewer.setMessage(new byte[0], false);

            }
            else if (menu == menuItemClearList)
            {
                reflectedEntryList.clear();
                
                //Reload the request table
                ((AbstractTableModel)this.getModel()).fireTableDataChanged();
                
                // Clear the parameters table
                ((ParametersTableModel)parametersTable.getModel()).reloadValues(new ReflectedEntry());
                
                // Clear request/response 
                requestViewer.setMessage(new byte[0], true);
                responseViewer.setMessage(new byte[0], false);

            }
        }
        
        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend)
        {
            // Reloading the Request/Response tabs
            ReflectedEntry reflectedEntry = reflectedEntryList.get(row);
            requestViewer.setMessage(reflectedEntry.requestResponse.getRequest(), true);
            responseViewer.setMessage(reflectedEntry.requestResponse.getResponse(), false);
            currentlyDisplayedItem = reflectedEntry.requestResponse;
            
            // Reloading the Parameters list
            parametersTable.reloadValues(reflectedEntry);
            super.changeSelection(row, col, toggle, extend);
        }        
    }
    
    // Parameters table
    private static class ParametersTableModel extends AbstractTableModel
    {
        ReflectedEntry reflectedEntry;
        
        public ParametersTableModel()
        {
            this.reflectedEntry = new ReflectedEntry();
        }
        public void reloadValues(ReflectedEntry reflectedEntry)
        {
            this.reflectedEntry = reflectedEntry;
            this.fireTableDataChanged();
        }
        
        @Override
        public Object getValueAt(int rowIndex, int columnIndex)
        {
            return reflectedEntry.parameters.get(rowIndex)[columnIndex];
        }
         @Override
        public int getColumnCount()
        {
            return 3;
        }
        @Override
        public int getRowCount()
        {
            return reflectedEntry.parameters.size();
        }
        
        @Override
        public String getColumnName(int columnIndex)
        {
            switch (columnIndex)
            {
                case 0:
                    return "Parameter name";
                case 1:
                    return "Parameter value";
                case 2:
                    return "Reflected value";
                default:
                    return "";
            }
        }
        @Override
        public Class<?> getColumnClass(int columnIndex)
        {
            return String.class;
        }
    }
    
    private class ParametersTable extends JTable implements ActionListener
    {
        private JPopupMenu popupMenu;
        private JMenuItem menuItemScannerParameter;
        
        public ParametersTable(TableModel tableModel)
        {
            super(tableModel);
            
            // Creating popup menu
            popupMenu = new JPopupMenu();
            menuItemScannerParameter = new JMenuItem("Scan parameter");
            menuItemScannerParameter.addActionListener(this);
            popupMenu.add(menuItemScannerParameter);
            this.setComponentPopupMenu(popupMenu);
        }
        private void reloadValues(ReflectedEntry reflectedEntry) 
        {
            ((ParametersTableModel)this.getModel()).reloadValues(reflectedEntry);
        }
        
        @Override
        public void actionPerformed(ActionEvent event) 
        {               
            int row = this.getSelectedRow();
            if (row == -1)
                return;
            ReflectedEntry reflectedEntry = ((ParametersTableModel)this.getModel()).reflectedEntry;
            List<int[]> param = new ArrayList<> ();
            param.add(reflectedEntry.requestResponse.getRequestMarkers().get(row));
            callbacks.doActiveScan(reflectedEntry.url.getHost(), reflectedEntry.url.getPort(), 
                    reflectedEntry.url.getProtocol().toLowerCase().equals("https"), reflectedEntry.requestResponse.getRequest(), param);
        }
    }
    
    //
    // Class to hold details of each reflected entry
    //
    private static class ReflectedEntry
    {
        final IHttpRequestResponseWithMarkers requestResponse;  // Request and response
        final URL url;                                          // Request URL
        final String method;                                    // Method used in the request
        List<String[]> parameters;                              // Parameter names with the values
        final String tool;                                      // Tool name from which the request was sent
        
        ReflectedEntry()
        {
            requestResponse = null;
            url = null;
            tool = null;
            method = null;
            parameters = new ArrayList<>();
        }
        
        ReflectedEntry(IHttpRequestResponseWithMarkers requestResponse, URL url, String method, List<String[]> parameters, String tool)
        {
            
            this.requestResponse = requestResponse;
            this.url = url;
            this.method = method;
            this.parameters = parameters;
            this.tool = tool;
        }
    }
}

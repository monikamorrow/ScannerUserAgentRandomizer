package burp;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringReader;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

public class BurpExtender implements IBurpExtender, IHttpListener
{
    private SecureRandom sr;
    private PrintWriter mStdOut;
    private PrintWriter mStdErr;
    private String mFilename;
    private List<String> mStrUserAgentList;
    
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        callbacks.setExtensionName("Scanner User Agent Randomizer");

        mStdOut = new PrintWriter(callbacks.getStdout(), true);
        mStdErr = new PrintWriter(callbacks.getStderr(), true);
        
        StartRandom();
        mFilename = "UserAgentStrings.txt"; // Derived from http://www.danmorgan.net/random-user-agent.phps
        mStrUserAgentList = new ArrayList<>();
        LoadUserAgentStrings(mFilename);

        callbacks.registerHttpListener(this);
    }
    
    @Override
    public void processHttpMessage(int toolFlag,
            boolean messageIsRequest,
            IHttpRequestResponse messageInfo)
    {
        mStdOut.println("processHttpMessage called");
        if(toolFlag == IBurpExtenderCallbacks.TOOL_SCANNER)
        {
            if(messageIsRequest)
            {
                messageInfo = ReplaceUserAgent(messageInfo);
            }
        }     
    }
    
    private IHttpRequestResponse ReplaceUserAgent(IHttpRequestResponse messageInfo)
    {
        String message = new String(messageInfo.getRequest());
        
        String search = "User-Agent: ";
        String replace = mStrUserAgentList.get(sr.nextInt(mStrUserAgentList.size()));
        
        StringBuilder newString = new StringBuilder(message.length() - message.length() + message.length());
        
        try {
            BufferedReader reader = new BufferedReader(new StringReader(message));
            String line;

            while((line = reader.readLine()) != null) {
                if(line != null) {
                    if(line.contains(search)) {
                        line = search + replace;
                    }
                    newString.append(line).append("\r\n");                 }
            }
        } catch (IOException e) {
            System.out.println("Error replacing text: " + e.getMessage());
        }
        
        messageInfo.setRequest(newString.toString().getBytes());
        return messageInfo;
    }

    private void LoadUserAgentStrings(String filename)
    {
        BufferedReader br = null;
        try {
            br = new BufferedReader(new FileReader(filename));
            String line;
            while ((line = br.readLine()) != null) {
                mStrUserAgentList.add(line);
            }
            br.close();
        } catch (FileNotFoundException e) {
            mStdErr.println("File Not Found Exception: " + e.getMessage());
        } catch (IOException e) {
            mStdErr.println("IO Exception: " + e.getMessage());
        } finally {
            try {
                if(br != null) {
                    br.close();
                }
            } catch (IOException e) {
                mStdErr.println("IO Exception on close: " + e.getMessage());
            }
        }
    }
    
    private void StartRandom()
    {
        try {
            sr = SecureRandom.getInstance("SHA1PRNG", "SUN");
            sr.nextInt();
        } catch (NoSuchAlgorithmException e) {
            System.out.println("No Such Algorithm Exception: " + e.getMessage());
        } catch (NoSuchProviderException e) {
            System.out.println("No Such Provider Exception: " + e.getMessage());
        }    
    }
        
}

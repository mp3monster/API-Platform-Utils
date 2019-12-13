//license : http://creativecommons.org/licenses/by/4.0/
//Creative Commons License
//This work is licensed under a Creative Commons Attribution 4.0 International License
// CC BY

// documentation for the API used by this utility are documented at https://docs.oracle.com/en/cloud/paas/api-platform-cloud/manage-apis.html

import groovy.json.*
import java.net.URLConnection
import javax.net.ssl.*
import groovy.transform.Field
import java.util.regex.*;  


class PROPS
{
    public static final String IDCSPROP = "IDCS"
    public static final String SERVERPROP = "server"
    public static final String USERNAMEPROP = "username"
    public static final String SCOPEPROP = "scope"
    public static final String DISPLAYPROP = "display"

    public static final String PROPFILENAMEDEFAULT = 'tool.properties'
    public static final String GATEWAYPROPS = "gateways"
    public static final String REPORTFNPROP = "reportFilename"


    public static final String YPROPVAL = "y";
    public static final String YESPROPVAL = "yes";
    public static final String TPROPVAL = "t";
    public static final String TRUEPROPVAL = "true";

    public static final int AppMatching = 0;
    public static final int APIMatching = 1;
    public static final int PlanMatching = 2;
    public static final int ServiceMatching = 3;

    public static final String APIVALIDATION = "APINameExpr";
    public static final String APPVALIDATION = "AppNameExpr";
    public static final String PLANVALIDATION = "PlanNameExpr";
    public static final String SERVICEVALIDATION = "ServiceNameExpr";

}

DisplayAll = false // allows us to pretty print all the API calls if necessary


@Field final POLICYPREFIX = "o:";

DefaultFileName = "report.csv";
ReportFileName = DefaultFileName;
// defines the filename to be used


@Field final SEP = "," // the delimiter/separator to use

// certificate by pass ====================
// http://codingandmore.blogspot.co.uk/2011/07/json-and-ssl-in-groovy-how-to-ignore.html

class OverideHostnameVerifier implements HostnameVerifier
{
    boolean verify(String hostname,
                   SSLSession session)
    { return true }
}

class TrustManager implements X509TrustManager
{

    public java.security.cert.X509Certificate[] getAcceptedIssuers()
    {
        return null
    }

    public void checkClientTrusted(
            java.security.cert.X509Certificate[] certs, String authType)
    {
    }

    public void checkServerTrusted(
            java.security.cert.X509Certificate[] certs, String authType)
    {}
}

TrustManager[] trustAllCerts = new TrustManager[1]
trustAllCerts[0] = new TrustManager()
source = new Source()

// ================================================================

class Source
{
    public String clientId = null;
    public String clientSecret = null;
    public String idcs = null;
    public String scope = null;

    public String uName = null;
    public String password = null;
    public String svr = null;

    private String authString = null;

    boolean usingIDCS()
    {
        return (idcs != null);
    }


    // verify the payload is configured - inOut ensures the right context is applied to any errors
    void applyAssertions(String inOut)
    {
        assert ((uName != null) && (uName.size() > 0)): "No username for " + inOut
        assert ((password != null) && (password.size() > 0)): "No Password for " + inOut
        assert ((svr != null) && (svr.size() > 0)): "No server for " + inOut

        if (usingIDCS())
        {
            assert ((idcs != null) && (idcs.size() > 0)): "IDCS not configured for " + inOut
            assert ((clientId != null) && (clientId.size() > 0)): "ClientId not configured for " + inOut
            assert ((clientSecret != null) && (clientSecret.size() > 0)): "ClientSecret not configured for " + inOut
        }
    }

// core API logic from here onward
// provide a function that consistently builds the authentication string to send to the API Platform

    String getAuthString()
    {
        if (authString != null)
        {
            return authString
        }

        final String ENC = "UTF-8"
        String combi = clientId + ":" + clientSecret;
        String authHeader = "Basic " + Base64.getEncoder().encodeToString(combi.getBytes())

        if (usingIDCS())
        {
            try
            {
                URL url = new URL(idcs)
                HttpsURLConnection con = (HttpsURLConnection) url.openConnection()
                con.setRequestMethod("POST")
                con.setRequestProperty("Authorization", authHeader)
                con.setRequestProperty("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
                con.setRequestProperty("Accept", "application/json")
                con.setDoOutput(true)

                try
                {
                    PrintStream os = new PrintStream(con.getOutputStream())

                    StringBuilder sb = new StringBuilder("grant_type=password&username=")
                    sb.append(URLEncoder.encode(uName, ENC))

                    sb.append("&scope=")
                    sb.append(URLEncoder.encode(scope, ENC))

                    sb.append("&password=")
                    sb.append(URLEncoder.encode(password, ENC))

                    os.print(sb.toString())
                    os.close()
                }
                catch (Exception err)
                {
                    System.out.println("error trying to produce URL\n" + err.getMessage())
                }

                if (con.getResponseCode() == HttpURLConnection.HTTP_OK)
                {
                    BufferedReader reader = new BufferedReader(new InputStreamReader(con.getInputStream()))
                    String line
                    StringBuilder access = new StringBuilder()
                    while ((line = reader.readLine()) != null)
                    {
                        access.append(line)
                    }

                    def json = new JsonSlurper().parseText(access.toString())
                    authString = "Bearer " + json.access_token
                }
                else
                {
                    throw new Exception("that didn't go very well -- response = " + con.getResponseCode())
                }
            }
            catch (Exception err)
            {
                System.err.println("Err getting token:\n" + err.getMessage())
                System.err.println(err.getStackTrace())
                System.exit(-1)

            }
        }
        else
        {
            // setup inPassword string
            final String authStringPlain = uName + ":" + password
            authString = "Basic " + (authStringPlain.getBytes().encodeBase64().toString())
        }
        return authString
    }

    void printConnection(String inOut)
    {
        String indent = "   "
        println("Connection is " + inOut)

        println(indent + "Client Id:" + clientId + "\n")
        println(indent + "Client Secret:" + clientSecret + "\n")
        println(indent + "IDCS Service:" + idcs + "\n")
        println(indent + "Scope:" + scope + "\n")
        println(indent + "Username:" + uName + "\n")
        println(indent + "Password:" + password + "\n")
        println(indent + "Server:" + svr + "\n")
        println(indent + "Auth Param:" + authString + "\n")
    }
}



void DisplayHelp()
{
    String HELPSTR = "================================================\nHelp:\n" +
                     "The following values are needed via the command line parameters\n" +
                     "  - password - for the user identified in the config file\n" +
                     "When connecting with IDCS the following are also needed:\n" +
                     "  - client Id\n" +
                     "  - client secret\n" +
                     "The following information needs to be provided by a properties file (tools.properties):\n" +
                     "  - " + PROPS.IDCSPROP + "\n" +
                     "  - " + PROPS.SCOPEPROP + "\n" +
                     "  - " + PROPS.USERNAMEPROP + "\n" +
                     "  - " + PROPS.SERVERPROP + "\n" +
                     "  - " + PROPS.REPORTFNPROP + " filename for the report to be written to\n" +
                     "  - " + PROPS.DISPLAYPROP + " displays all the diagnostic info\n" +
                     " The app if completing successfully will display some stats that will help understand licensing position\n" +
                     "================================================\n"
    System.out.println(HELPSTR)
    System.exit(0)
}


String propFilename = PROPS.PROPFILENAMEDEFAULT
Properties props = new Properties()
File propFile = new File(propFilename)
props.load(propFile.newDataInputStream())

ConfigObject config = new ConfigSlurper().parse(props)


source.svr = config.get(PROPS.SERVERPROP)
if (source.svr != null)
{
    source.svr = source.svr.trim()
}

source.uName = config.get(PROPS.USERNAMEPROP)
if (source.uName != null)
{
    source.uName = source.uName.trim()
}

source.scope = config.get(PROPS.SCOPEPROP)
if (source.scope != null)
{
    source.scope = source.scope.trim()
}

source.idcs = config.get(PROPS.IDCSPROP)
if (source.idcs != null)
{
    source.idcs = source.idcs.trim()
}



ReportFileName = config.get(PROPS.REPORTFNPROP)
if (ReportFileName != null)
{
    ReportFileName = ReportFileName.trim()
}

displayAllStr = config.get(PROPS.DISPLAYPROP)
if ((displayAllStr != null) && (displayAllStr.equalsIgnoreCase(PROPS.YPROPVAL) || displayAllStr.equalsIgnoreCase
        (PROPS.YESPROPVAL) || displayAllStr.equalsIgnoreCase(PROPS.TPROPVAL) ||
                                displayAllStr.equalsIgnoreCase(PROPS.TRUEPROPVAL)))
{
    DisplayAll = true
}
else
{
    DisplayAll = false
}


//===============
// handle CLI
if (DisplayAll)
{
    println("at CLI with " + args.size() + " args\n" + args.toString())
}
if (args.size() > 0)
{
    try
    {
        if (args[0] == "-h")
        {
            DisplayHelp()
        }
        else
        {
            if (args.size() >= 1)
            {
                source.password = args[0]
            }
            if (args.size() >= 2)
            {
                source.clientId = args[1]
                source.clientSecret = args[2]
            }
        }

    }
    catch (Exception err)
    {
        if (DisplayAll)
        {
            println(err.getMessage())
            err.printStackTrace()
        }
        DisplayHelp()
        System.exit(0)
    }
}
else
{
    DisplayHelp()
}

if (DisplayAll)
{
    source.printConnection("source")
}

// verify all the parameters
try
{
    assert ((ReportFileName != null) && (ReportFileName.size() > 0)): "report filename not configured"
    source.applyAssertions("Source")

}
catch (Exception err)
{
    println(err.getMessage() + "\n")
    if (DisplayAll)
    {
        err.printStackTrace()
    }
    DisplayHelp()
    System.exit(0)
}

///=================================================

// this implements a nanming convention check
void validateName(int listType, Source source, String nameExpression, File nameReportFile, String errorMsg)
{
    String query = null
    String result = "";
    String resultAccepted = "";

    if (DisplayAll)
    {
        println ("Testing " + listType + " for " + nameExpression);
    }

    switch (listType)
    {
        case PROPS.AppMatching:
            query = source.svr + "/apiplatform/management/v1/applications";
            break

        case PROPS.APIMatching:
            query = source.svr + "/apiplatform/management/v1/apis";
            break

        case PROPS.PlanMatching:
            query = source.svr + "/apiplatform/management/v1/plans";
            break

        case PROPS.ServiceMatching:
            query = source.svr + "/apiplatform/management/v1/services";
            break

        default:
            if (DisplayAll)
            {
                println("Unexpected option");
            }
            throw new Exception ("Illegal name check");
    }

    def listURL = new URL(query).openConnection();
    listURL.setRequestProperty("Authorization", source.getAuthString());
    JSONData = new JsonSlurper().parse(listURL.getInputStream());

    int count = JSONData.count;
    for (int idx = 0; idx < count; idx++)
    {
        legalName = Pattern.matches (nameExpression, JSONData.items[idx].name);

        if (legalName)
        {
            if (DisplayAll)
            {
                println (JSONData.items[idx].id + " " +  JSONData.items[idx].name + " --- ok \n");
            }
        }
        else
        {
            String detailQuery = query+"/"+JSONData.items[idx].id+"/";
            def detailURL = new URL(detailQuery).openConnection();
            detailURL.setRequestProperty("Authorization", source.getAuthString());
            JSONDetail = new JsonSlurper().parse(detailURL.getInputStream());
            String msg = errorMsg + ":" +  JSONData.items[idx].name + "(" + JSONData.items[idx].id + ") " + 
                        " created by:" + JSONDetail.createdBy + 
                        " updated by:" + JSONDetail.updatedBy + 
                        " updated on:" + JSONDetail.updatedAt;
            if (nameReportFile != null)
            {
                nameReportFile.append (msg + "\n");
            }

            if (DisplayAll)
            {
                println (msg);
            }
            //println(new JsonBuilder(JSONDetail).toPrettyString())


        }
    }

}


// this implements a nanming convention check
void validateRequiredPolicies(Source source, ArrayList requiredRequestPolicies, ArrayList requiredResponsePolicies, File report)
{
    String query = source.svr + "/apiplatform/management/v1/apis";
    String result = "";
    String resultAccepted = "";

    def listURL = new URL(query).openConnection();
    listURL.setRequestProperty("Authorization", source.getAuthString());
    JSONData = new JsonSlurper().parse(listURL.getInputStream());

    int count = JSONData.count;
    for (int idx = 0; idx < count; idx++)
    {

        String detailQuery = query+"/"+JSONData.items[idx].id+"/";
        def detailURL = new URL(detailQuery).openConnection();
        detailURL.setRequestProperty("Authorization", source.getAuthString());
        JSONDetail = new JsonSlurper().parse(detailURL.getInputStream());

        //println(new JsonBuilder(JSONDetail).toPrettyString())

        ArrayList requestIds = JSONDetail.implementation.executions.request;
        ArrayList responseIds = JSONDetail.implementation.executions.response;
        ArrayList tempRequiredRequestPolicies = requiredRequestPolicies.clone();
        ArrayList tempRequiredResponsePolicies = requiredResponsePolicies.clone();

        for (int polIdx = 0; polIdx < JSONDetail.implementation.policies.size(); polIdx++)
        {
            if (requestIds.contains (JSONDetail.implementation.policies[polIdx].id))
            {
                // strip away Oracle's prefix chars
                String policyName = JSONDetail.implementation.policies[polIdx].type.substring (POLICYPREFIX.length());
                if (tempRequiredRequestPolicies.contains(policyName))
                {
                    boolean removed = tempRequiredRequestPolicies.remove(policyName);
                    if (DisplayAll)
                    {
                        println (JSONData.items[idx].name + " correctly contains required policy " + policyName + " - removed " + removed);
                    }
                }
            }
            else if (responseIds.contains (JSONDetail.implementation.policies[polIdx].id))
            {
                // strip away Oracle's prefix chars
                String policyName = JSONDetail.implementation.policies[polIdx].type.substring (POLICYPREFIX.length());
                if (tempRequiredResponsePolicies.contains(policyName))
                {
                    boolean removed = tempRequiredResponsePolicies.remove(policyName);
                    if (DisplayAll)
                    {
                        println (JSONData.items[idx].name + " correctly contains required response policy " + JSONDetail.implementation.policies[polIdx].type + " - removed " + removed);
                    }                    
                }
            }
            
        }
    
        if (tempRequiredRequestPolicies.size() > 0)
        {
            String missingPolicies = tempRequiredRequestPolicies.toString();
            String msg = JSONData.items[idx].name + "(" + JSONData.items[idx].id + ") " + 
                    " missing request policies:" + missingPolicies;
            if (report != null)
            {
                report.append (msg + "\n");
            }
            if (DisplayAll)
            {
                println (msg);
            }
        }
        if (tempRequiredResponsePolicies.size() > 0)
        {
            String missingPolicies = tempRequiredResponsePolicies.toString();
            String msg = JSONData.items[idx].name + "(" + JSONData.items[idx].id + ") " + 
                    " missing response policies:" + missingPolicies;
            if (report != null)
            {
                report.append (msg + "\n");
            }
            if (DisplayAll)
            {
                println (msg);
            }
        }

    }

}



// convert the named property into an array list
ArrayList RequiredPolicyList (String property, ConfigObject config)
{
    ArrayList result = new ArrayList();

    String propList = config.get(property);
    if (propList != null)
    {
        String[] tempList = propList.split(",");

        for (int idx = 0; idx < tempList.length; idx++)
        {
            result.add(tempList[idx].trim());
        }
    }

    return result;
}


//==================================================
// main

println("report file will be " + ReportFileName);
File file = new File(ReportFileName);

if (file.exists())
{
    file.delete()
    if (DisplayAll)
    {
        println("deleted old version of " + ReportFileName)
    }
}
file.createNewFile()

// setup password string
// configure HTTP connectivity inc ignoring certificate validation
SSLContext sc = SSLContext.getInstance("SSL")
sc.init(null, trustAllCerts, new java.security.SecureRandom())
HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory())
HttpsURLConnection.setDefaultHostnameVerifier((HostnameVerifier) new OverideHostnameVerifier())

ArrayList masterRequestList = RequiredPolicyList("RequiredRequestPolicies", config);
ArrayList masterResponseList = RequiredPolicyList("RequiredResponsePolicies", config);

try
{
    String testPattern = config.get(PROPS.APIVALIDATION);
    if (testPattern != null)
    {
        testPattern = testPattern.trim();
        validateName(PROPS.APIMatching, source, testPattern, file, "API name invalid");
    }

    validateRequiredPolicies(source, masterRequestList, masterResponseList, file);

    testPattern = config.get(PROPS.APPVALIDATION);
    if (testPattern != null)
    {
        testPattern = testPattern.trim();
        validateName(PROPS.AppMatching, source, testPattern, file, "Application name invalid");
    }


    testPattern = config.get(PROPS.PLANVALIDATION);
    if (testPattern != null)
    {
        testPattern = testPattern.trim();
        validateName(PROPS.PlanMatching, source, testPattern, file, "Plan name invalid");
    }

    testPattern = config.get(PROPS.SERVICEVALIDATION);
    if (testPattern != null)
    {
        testPattern = testPattern.trim();
        validateName(PROPS.ServiceMatching, source, testPattern, file, "Service name invalid");
    }



}
catch (Exception err)
{
    println(err.getMessage());
    err.printStackTrace();
}

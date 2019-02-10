//license : http://creativecommons.org/licenses/by/4.0/
//Creative Commons License
//This work is licensed under a Creative Commons Attribution 4.0 International License
// CC BY

import groovy.json.*
import java.net.URLConnection
import javax.net.ssl.*

DisplayAll = false // allows us to pretty print all the API calls if necessary

// API call header property
Authorization = "Authorization"

public class CONFIGS
{
    public static final String VERSIONINFOPROP = "versionInfo"
    public static final String DRAFTPOLICIESINFOPROP = "draftPolicyInfo"
    public static final String POLICYINFOPROP = "policyInfo"
    public static final String EXCLUDEPROP = "exclusions"
    public static final String CHANGEINFOPROP = "changeInfo"

    public static final String MATCHAPP = "APP"
    public static final int MATCHAPPNO = 0
    public static final String MATCHAPI = "API"
    public static final int MATCHAPINO = 1
    
    public static final String MATCHTYPEPROP = "matchType"
    public static final String SINGLEFILEOUTPUTPROP = "useSingleFile"
    public static final String IDCSPROP = "IDCS"
    public static final String SERVERPROP = "server"
    public static final String USERNAMEPROP = "username"
    public static final String SCOPEPROP = "scope"
    public static final String TARGETPOLICYNAMEPROP = "TargetPolicy"
    public static final String DISPLAYPROP = "display"

    public static final String YPROPVAL = "y"
    public static final String YESPROPVAL = "yes"
    public static final String TPROPVAL = "t"
    public static final String TRUEPROPVAL = "true"


}


public class MD
{
// string for printing the output
    public static final String NL = "\n"
    public static final String H1 = " #"
    public static final String H2 = " ##"
    public static final String H3 = " ###"
    public static final String LST = " * "
    public static final String BOLD = "**"
    public static final String Separator = "  "
    public static final String Rule = "---" + NL
    public static final String APIsHeader = "APIs"
    public static final String APPsHeader = "APPs"
    public static final String VersionHeader = "Version"
    public static final String ChangeHeader = " Creation & Amendment"
    public static final String PolicyHeader = "Policies"
    public static final String RequestsHeader = "Requests"
    public static final String ResponsesHeader = "Responses"
    public static final String CreatedONLabel = "Created On:"
    public static final String UpdatedONLabel = "Updated On:"

    public static final String VersionNoLabel = "Version No."
    public static final String StateLabel = "State:"
    public static final String IterationLabel = "Iteration No:"

    public static final String PolicyTypeLabel = "Policy:"

    public static final String NOREQUESTTODISPLAY = "-- No Requests to Display --"
    public static final String NORESPONSETODISPLAY = "-- No Responses to Display --"

    public static final String noDescription = " -- No Description Available --"
    public static final String FilePostfix = ".md"
    public static final String DefaultFileName = "APIDoc"
    public static final String AppRef = "references.applications"
}

// if defaults are set then calling with the default values will attempted
def String uname = null
def String password = null
def String svr = null

DisplayHelp = "-h"

MatchType = CONFIGS.MATCHAPINO

TargetName = null

SingleFileName = MD.DefaultFileName
// default to true so theat the finemae in the API NAME
// if the -f option is used then this goes to false and SingleFileName is set
def boolean MultiFile = true

// these flags define what information gets written
IncludeChangeInfo = true
IncludeVersionInfo = true
IncludePolicyInfo = true
IncludeAppInfo = true
IncludeDraftPoliciesInfo = true
CheckForExclusion = false

COMMENTEXCLUDETEXT = "EXCLUDE"

idcs = null
scope = null


final String PROPFILENAMEDEFAULT = 'tool.properties'


String propFilename = PROPFILENAMEDEFAULT
Properties props = null
File propFile = null
ConfigObject config = null


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

// ================================================================


// this function takes a json object containing the known APIs and
// evaluates the API details to see if they match. If they MATCHED
// if successful add it to the list provided and return trhe amended list
ArrayList matchAPIName(Object apiData, ArrayList apis, String name, String apiDataURL)
{
    if (DisplayAll)
    {
        println("evaluating >" + name + "< against vanity name>" + apiData.vanityName + "< and internal name >" + apiData.name + "<")
    }

    // if we dont have a match value then we just add it to the list
    if (name != null)
    {
        // if the name isn't null then we can eval the contains path.  If the name cant evaluate then try the vanity name
        if (((apiData.name != null) && (apiData.name.contains(name))) ||
            ((apiData.vanityName != null) && (apiData.vanityName.contains(name))))
        {
            apis.add(apiDataURL)
            if (DisplayAll)
            {
                println("Matched API " + apiData.name + " --> " + apiData.vanityName)
            }
        }
    }
    else
    {
        apis.add(apiDataURL);
        if (DisplayAll)
        {
            println("Matched API " + apiData.name + " --> " + apiData.vanityName)
        }
    }
    return apis
}

// look to match against App names
ArrayList matchAppName(Object apiData, ArrayList apis, String name, String apiDataURL)
{
    try
    {
        if (apiData.links != null)
        {
            for (apiRefCtr = 0; apiRefCtr < apiData.links.size(); apiRefCtr++)
            {
                // the reference links to an Applicaiton - so record the association
                if (apiData.links[apiRefCtr].rel.equals(AppRef))
                {
                    if (DisplayAll)
                    {
                        println("Found APP ref for " + apiData.name)
                    }
                    def app = new URL(apiData.links[apiRefCtr].href).openConnection()
                    app.setRequestProperty(Authorization, authString)
                    def appData = new JsonSlurper().parse(app.getInputStream())
                    // if there is no match name we add everything to the list
                    if ((appData.items != null) && (appData.items[0] != null) && (appData.items[0].name != null))
                    {
                        if ((name == null) || (appData.items[0].name.contains(name)))
                        {
                            apis.add(apiDataURL);
                            if (DisplayAll)
                            {
                                println("MATCHED App name:" + appData.items[0].name + " with " + name)
                            }

                        }
                        else
                        {
                            if (DisplayAll)
                            {
                                println("NOT matched App name: " + appData.items[0].name)
                            }
                        }
                    }
                }
            }
        }
        else
        {
            println("Found no links ref for " + apiData.name)
        }
    }
    catch (FileNotFoundException err)
    {
        if (DisplayAll)
        {
            println("No URL for " + err.getMessage())
        }
    }

    return apis
}

// evaluate how to process the policies and then build output display
StringBuffer processPolicies(Object apiData, StringBuffer sb, HashMap policyMetadata)
{
    //boolean addHeader = true
    HashMap policyTexts = new HashMap()

    for (policyCtr = 0; policyCtr < apiData.implementation.policies.size(); policyCtr++)
    {
        StringBuffer line = new StringBuffer()
        // if the policy is a draft and drafts are accepted or not a draft
        if (((IncludeDraftPoliciesInfo) && (apiData.implementation.policies[policyCtr].draft == true)) ||
            (apiData.implementation.policies[policyCtr].draft != true))
        {
            // has the policy entry got a defined type - it should have
            if (apiData.implementation.policies[policyCtr].type != null)
            {
                if (DisplayAll)
                {
                    println(MD.NL + "policy to evaluate :" + new JsonBuilder(
                            apiData.implementation.policies[policyCtr]).
                            toPrettyString())
                }

                def policyMetadataEntry = policyMetadata.get(apiData.implementation.policies[policyCtr].type)

                line.append(MD.BOLD + MD.PolicyTypeLabel + MD.BOLD + policyMetadataEntry.name)
                String policyDescription = null

                // get the description if there isnt a specific one for this policy instance, retrieve the policy standard definition
                policyDescription = apiData.implementation.policies[policyCtr].comments
                if (policyDescription != null)
                {
                    policyDescription = policyDescription.trim()

                }

                if (policyMetadataEntry != null)
                {
                    if ((policyDescription == null) || (policyDescription.length() == 0))
                    {
                        policyDescription = policyMetadataEntry.description
                        if (DisplayAll)
                        {
                            println("getting policy description from the cached metadata - " + policyMetadataEntry.description)
                        }
                    }
                }

                // evaluate and action exclusion if set
                if ((policyDescription != null) &&
                    CheckForExclusion &&
                    (policyDescription.endsWith(COMMENTEXCLUDETEXT)))
                {
                    if (DisplayAll)
                    {
                        println("Applying exclusion to " + policyMetadataEntry.name)
                    }
                    // instruction to exclude this policy has been allocated
                    policyDescription = null
                    line = null
                }

                if (policyDescription != null)
                {
                    line.append(" : " + policyDescription + MD.NL)
                }
                if (line != null)
                {
                    line.append(MD.NL)
                }
                if (DisplayAll)
                {
                    println("policy info:" + new JsonBuilder(apiData.implementation.policies[policyCtr]).
                            toPrettyString() + MD.NL + MD.NL)
                }
            }
        }
        policyTexts.put(apiData.implementation.policies[policyCtr].id, line)
    }


    sb.append(MD.H2 + MD.Separator + MD.PolicyHeader + MD.NL)
    sb.append(MD.H3 + MD.Separator + MD.RequestsHeader + MD.NL)
    int lineCount = 0;
    for (requestCtr = 0; requestCtr < apiData.implementation.executions.request.size(); requestCtr++)
    {
        requestLine = policyTexts.get(apiData.implementation.executions.request[requestCtr])
        if (requestLine != null)
        {
            sb.append(requestLine)
            lineCount++
        }
    }

    if (lineCount == 0)
    {
        sb.append(MD.NOREQUESTTODISPLAY)
    }

    sb.append(MD.H3 + MD.Separator + MD.ResponsesHeader + MD.NL)
    lineCount = 0
    for (responseCtr = 0; responseCtr < apiData.implementation.executions.response.size(); responseCtr++)
    {
        responseLine = policyTexts.get(apiData.implementation.executions.response[responseCtr])
        if (responseLine != null)
        {
            sb.append(responseLine)
            lineCount++
        }
    }
    if (lineCount == 0)
    {
        sb.append(MD.NORESPONSETODISPLAY)
    }

    return sb
}


// put together the description of the policies
StringBuffer processAppDetails(StringBuffer sb, Object appObj, HashMap appDescCache, String svr, String authString)
{
    sb.append(MD.H2 + MD.Separator + MD.APPsHeader + MD.NL)
    sb.append(appObj.items[0].name)
    String description = null

    // get the app Description
    if (appDescCache.containsKey(appObj.items[0].id))
    {
        // have the description cached use that
        description = appDescCache.get(appObj.items[0].id)
        if (DisplayAll)
        {
            println("used description cache")
        }
    }
    else
    {
        // need to go look up the descriptions
        def appdescURL = new URL(svr + "/apiplatform/management/v1/applications/" + appObj.items[0].id).openConnection()
        appdescURL.setRequestProperty(Authorization, authString)
        def appDescObj = new JsonSlurper().parse(appdescURL.getInputStream())
        description = appDescObj.description
        appDescCache.put(appObj.items[0].id, description)
        if (DisplayAll)
        {
            println("looked up description")
            println(new JsonBuilder(appDescObj).toPrettyString())
        }
    }

    // have I managed to obtain a meaningful description text
    if ((description != null) && (description.length() > 0))
    {
        sb.append(": " + description + MD.NL)
    }

    return sb
}

void DisplayHelp()
{
    String recognizedValues = " - " + CONFIGS.YPROPVAL + "|" + CONFIGS.YESPROPVAL + "|" + CONFIGS.TPROPVAL + "|" + CONFIGS.TRUEPROPVAL + "\n"
    println("================================================\nHelp:\n" +
            "Requires command line parameters are:\n" +
            "   password \n" +
            "   properties file\n" +
            "If being used with a managed API Platform then additionally:\n" +
            "  Client Id and \n" +
            "  Client Secret need to be provided\n" +
            "Without these parameters the app will stop\n" +
            "The following values are taken from the configuration file:\n" +
            "   " + CONFIGS.SERVERPROP + " -- The API management platform \n" +
            "   " + CONFIGS.USERNAMEPROP + " -- username to authenticate with into the API Platform\n" +
            "   " + CONFIGS.IDCSPROP + " -- URL to the token service in IDCS (only required for managed API Platform)\n" +
            "   " + CONFIGS.SCOPEPROP + " -- IDCS scope value (only required for managed API Platform)\n" +
            "   " + CONFIGS.TARGETPOLICYNAMEPROP + " -- can contain part of a policy name - to filter the processed policies\n" +
            "   " + CONFIGS.MATCHTYPEPROP + " -- to define the match against an application or API the value musty be - " + CONFIGS.MATCHAPP + "|" + CONFIGS.MATCHAPI + "\n" +
            "   " + CONFIGS.POLICYINFOPROP + " -- to include policy information value must be one of " + recognizedValues +
            "   " + CONFIGS.DRAFTPOLICIESINFOPROP + " -- to include draft policy information value must be one of " + recognizedValues +
            "   " + CONFIGS.EXCLUDEPROP + " -- to observe the EXCLUDE indicator must be one of " + recognizedValues +
            "   " + CONFIGS.CHANGEINFOPROP + " -- to include details of when the policy was changed, value must be one of " + recognizedValues +
            "   " + CONFIGS.VERSIONINFOPROP + " -- to include version information this must be one of " + recognizedValues +
            "   " + CONFIGS.SINGLEFILEOUTPUTPROP + " -- to send all API docs to the same file, the value must be the " +
            "name of the output file" +
            " "  +
            "   " + CONFIGS.DISPLAYPROP + " -- to enable diagnostic information the value needs to be one of " + recognizedValues +
            "\nTool doc at: http://blog.mp3monster.org/2018/05/18/documenting-apis-on-the-oracle-api-platform\n")
    println("================================================\n")
    System.exit(0)
}


// as we need to process a number of config values the same way - this provides the standardised logic
boolean getConfigState(ConfigObject config, String property, boolean defaultVal)
{
    boolean set = defaultVal

    String valStr = config.get(property)
    if (valStr != null)
    {
        if ((valStr.equalsIgnoreCase(CONFIGS.YPROPVAL) ||
             valStr.equalsIgnoreCase(CONFIGS.YESPROPVAL) ||
             valStr.equalsIgnoreCase(CONFIGS.TPROPVAL) ||
             valStr.equalsIgnoreCase(CONFIGS.TRUEPROPVAL)))
        {
            set = true
        }
        else
        {
            set = false
        }
    }

    return set
}
//===============


// handle CLI
if (DisplayAll)
{
    println("at CLI with " + args.size() + " args\n" + args.toString())
}

props = new Properties();
propFile = new File(propFilename);
props.load(propFile.newDataInputStream())
config = new ConfigSlurper().parse(props)

println("1")

svr = config.get(CONFIGS.SERVERPROP)
uname = config.get(CONFIGS.USERNAMEPROP)
DisplayAll = getConfigState(config, CONFIGS.DISPLAYPROP, false)
IncludeVersionInfo = getConfigState(config, CONFIGS.VERSIONINFOPROP, false)
IncludeChangeInfo = getConfigState(config, CONFIGS.CHANGEINFOPROP, false)
IncludePolicyInfo = getConfigState(config, CONFIGS.POLICYINFOPROP, false)
CheckForExclusion = getConfigState(config, CONFIGS.EXCLUDEPROP, false)
IncludeDraftPoliciesInfo = getConfigState(config, CONFIGS.DRAFTPOLICIESINFOPROP, false)

println("5")

idcs = config.get(CONFIGS.IDCSPROP)
scope = config.get(CONFIGS.SCOPEPROP)
TargetName = config.get(CONFIGS.TARGETPOLICYNAMEPROP)
useIDCS = ((idcs != null) && (idcs.size() > 0))


SingleFileName = config.get(CONFIGS.SINGLEFILEOUTPUTPROP)
if (SingleFileName != null)
{
    SingleFileName.trim()

    if (SingleFileName.length() == 0)
    {
        println("Malformed filename parameter")
        SingleFileName = DefaultFileName + FilePostfix
    }
    else
    {
        // its a legitimate filename - so switch on single file
        if (DisplayAll)
        {
            "Single file target, filename is  " + SingleFileName
        }
        MultiFile = false
    }
}
else
{
    MultiFile = true

}

String matchCommand = config.get(CONFIGS.MATCHTYPEPROP)
MatchType = CONFIGS.MATCHAPINO
if (matchCommand != null)
{
    matchCommand = matchCommand.toUpperCase().trim()
}
if (matchCommand == CONFIGS.MATCHAPP)
{
    MatchType = CONFIGS.MATCHAPPNO
    if (DisplayAll)
    {
        println("Matching for App names")
    }
}
else if (matchCommand == CONFIGS.MATCHAPI)
{
    MatchType = CONFIGS.MATCHAPINO
    if (DisplayAll)
    {
        println("Matching for API names explicitly set")
    }
}

if (DisplayAll)
{
    println("Match Type set to" + matchCommand)
}


if (args.size() > 0)
{
    try
    {
        if (args.size() > 0)
        {
            if (args[0] == DisplayHelp)
            {
                DisplayHelp()
                System.exit(0)
            }
            else
            {
                password = args[0]
                propertiesFile = args[1]
            }

            if (args.size() > 2)
            {
                clientId = args[2]
                clientSecret = args[3]
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
    System.exit(0)
}

// verify all the parameters
try
{
    assert (uname.size() > 0): "No username"
    assert (password.size() > 0): "No password"
    assert (svr.size() > 0): "No server"
}
catch (Exception err)
{
    println(err.getMessage() + "\n")
    println("Error 2")
    if (DisplayAll)
    {
        err.printStackTrace()
    }
    DisplayHelp()
    System.exit(0)
}

// main

def HashMap policyMetadata = new HashMap();
def ArrayList apis = new ArrayList() // k=api.id, v=https://docs.oracle.com/en/cloud/paas/api-platform-cloud/apfrm/op-apis-%7BapiId%7D-get.html

// setup password string
// configure HTTP connectivity inc ignoring certificate validation
SSLContext sc = SSLContext.getInstance("SSL");
sc.init(null, trustAllCerts, new java.security.SecureRandom());
HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
HttpsURLConnection.setDefaultHostnameVerifier((HostnameVerifier) new OverideHostnameVerifier());


if (useIDCS)
{
    authString = "Bearer " + getAccessToken(idcs, clientId, clientSecret, uname, password, scope)
}
else
{
    // setup password string
    final String authStringPlain = uname + ":" + password
    authString = "Basic " + (authStringPlain.getBytes().encodeBase64().toString())

}

try
{
    // get policy metadata
    def callPoliciesMetadata = new URL(svr + "/apiplatform/management/v1/policies/metadata").openConnection()
    callPoliciesMetadata.setRequestProperty(Authorization, authString)
    def jsonPolicyMetaList = new JsonSlurper().parse(callPoliciesMetadata.getInputStream())
    if (DisplayAll)
    {
        println("****** policy meta data *****")
        println(new JsonBuilder(jsonPolicyMetaList).toPrettyString())
        println("*****************************")
    }


    for (policyMetaIdx = 0; policyMetaIdx < jsonPolicyMetaList.count; policyMetaIdx++)
    {
        policyMetadata.put(jsonPolicyMetaList.items[policyMetaIdx].type, jsonPolicyMetaList.items[policyMetaIdx])
    }

    // get the API list and then iterate through pulling the API information - record the API info into a map
    def listAPIs = new URL(svr + "/apiplatform/management/v1/apis").openConnection()
    listAPIs.setRequestProperty(Authorization, authString)
    def listAPIData = new JsonSlurper().parse(listAPIs.getInputStream())


    for (idx = 0; idx < listAPIData.count; idx++)
    {
        def apiDataURL = svr + "/apiplatform/management/v1/apis/" + listAPIData.items[idx].id
        if (DisplayAll)
        {
            println("requesting : " + apiDataURL)
        }
        def api = new URL(apiDataURL).openConnection()
        api.setRequestProperty(Authorization, authString)
        def apiData = new JsonSlurper().parse(api.getInputStream())

        switch (MatchType)
        {
            case CONFIGS.MATCHAPINO:
                apis = matchAPIName(apiData, apis, TargetName, apiDataURL)
                break

            case CONFIGS.MATCHAPPNO:
                apis = matchAppName(apiData, apis, TargetName, apiDataURL)
                break

            default:
                if (DisplayAll)
                {
                    println("Unknown match type! :" + MatchType)
                }
        }
    }
}
catch (Exception excep)
{
    if (DisplayAll)
    {
        excep.printStackTrace()
    }
}

if (DisplayAll)
{
    println("======================================")
    println("generating docs for " + apis.size() + " APIs")
}
def String fileName = null
def HashMap appDescCache = new HashMap()
// cache the app descriptions so we dont keep having to look it up
def File file = null
if (!MultiFile)
{
    fileName = SingleFileName + MD.FilePostfix
    if (DisplayAll)
    {
        println("Single File Output to " + fileName)
    }
    file = new File(fileName)
    if (file.exists())
    {
        file.delete()
        //println ("deleted old version of " + filename)
    }
    file.createNewFile()
}
// we have not been through all the apis noted their meta data and then allocated them to the unassigned list OR linked them to an app
for (apiCtr = 0; apiCtr < apis.size(); apiCtr++)
{
    StringBuffer sb = new StringBuffer()
    try
    {
        def api = new URL(apis[apiCtr]).openConnection()
        api.setRequestProperty(Authorization, authString)
        def apiData = new JsonSlurper().parse(api.getInputStream())

        if (MultiFile)
        {
            fileName = apiData.name + MD.FilePostfix
            file = new File(fileName)

            if (file.exists())
            {
                file.delete()
                //println ("deleted old version of " + fileName)
            }
            file.createNewFile()
        }

        sb.append(MD.H1 + MD.Separator)
        sb.append(apiData.name + MD.NL)
        if ((apiData.description != null) && (apiData.description.length() > 0))
        {
            sb.append(apiData.description + MD.NL)
        }
        else
        {
            sb.append(MD.noDescription + MD.NL)
        }

        if (IncludeVersionInfo)
        {
            if (DisplayAll)
            {
                println("Including version info for " + apiData.name)
            }
            sb.append(MD.H2 + MD.Separator + MD.VersionHeader + MD.NL)
            sb.append(MD.BOLD + MD.VersionNoLabel + MD.BOLD + apiData.version)
            sb.append(MD.Separator + MD.BOLD + MD.StateLabel + MD.BOLD + apiData.state + MD.NL)
            sb.append(MD.BOLD + MD.IterationLabel + MD.BOLD + apiData.iterationId + MD.NL)
        }

        if (IncludeChangeInfo)
        {
            if (DisplayAll)
            {
                println("Including change info for " + apiData.name)
            }
            sb.append(MD.H3 + MD.Separator + MD.ChangeHeader + MD.NL)
            sb.append(MD.BOLD + MD.CreatedONLabel + MD.BOLD + apiData.createdAt)
            sb.append(MD.Separator + MD.BOLD + MD.UpdatedONLabel + MD.BOLD + apiData.updatedAt + MD.NL)
        }

        // locate the app info and write
        if (IncludeAppInfo)
        {
            if (DisplayAll)
            {
                println("Including app info for " + apiData.name)
            }
            if (apiData.links != null)
            {
                for (linkCtr = 0; linkCtr < apiData.links.size(); linkCtr++)
                {
                    if ((apiData.links[linkCtr].rel != null) && (apiData.links[linkCtr].rel == MD.AppRef))
                    {
                        def appURL = new URL(apiData.links[linkCtr].href).openConnection()
                        appURL.setRequestProperty(Authorization, authString)
                        def appObj = new JsonSlurper().parse(appURL.getInputStream())
                        if ((appObj.items != null) && (appObj.items[0] != null) &&
                            (appObj.items[0].name != null))
                        {
                            sb = processAppDetails(sb, appObj, appDescCache, svr, authString)
                        }
                    }
                }
            }
        } // end of app info

        if (IncludePolicyInfo)
        {
            if (DisplayAll)
            {
                println("Including policy info for " + apiData.name)
            }
            // provide the policy info
            if (apiData.implementation.policies != null)
            {
                sb = processPolicies(apiData, sb, policyMetadata)
            }
        }

    }
    catch (Exception err)
    {
        err.printStackTrace()
    }
    if (!MultiFile)
    {
        sb.append(MD.NL + Rule)
    }
    if (DisplayAll)
    {
        println(sb.toString() + "\n ++++++++++++++++++++++++++++++++++++++++++++++++++++")
    }
    file.append(sb.toString())
}

// generates the IDCS access token string
public String getAccessToken(String idcs, String clientId, String clientSecret, String userName, String password,
                             String scope)
{
    final String ENC = "UTF-8"
    String accessToken = null
    String combi = clientId + ":" + clientSecret
    String authHeader = "Basic " + Base64.getEncoder().encodeToString(combi.getBytes())

    try
    {
        URL url = new URL(idcs);
        HttpsURLConnection con = (HttpsURLConnection) url.openConnection()
        con.setRequestMethod("POST")
        con.setRequestProperty(Authorization, authHeader)
        con.setRequestProperty("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
        con.setRequestProperty("Accept", "application/json")
        con.setDoOutput(true)

        try
        {
            PrintStream os = new PrintStream(con.getOutputStream())

            StringBuilder sb = new StringBuilder("grant_type=password&username=")
            sb.append(URLEncoder.encode(userName, ENC))

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
            String line;
            StringBuilder access = new StringBuilder()
            while ((line = reader.readLine()) != null)
            {
                access.append(line)
            }

            def json = new JsonSlurper().parseText(access.toString())
            accessToken = json.access_token
        }
        else
        {
            throw new Exception("Oh crap - that didn't go very well -- response = " + con.getResponseCode())
        }
    }
    catch (Exception err)
    {
        System.err.println("Err getting token:\n" + err.getMessage())
    }

    return accessToken
}

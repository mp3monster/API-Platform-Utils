// documentation on this Utility is available at - http://blog.mp3monster.org/2018/02/27/APIVersioning

import groovy.json.*
import java.net.URLConnection
import javax.net.ssl.*
import groovy.json.JsonBuilder


class CONFIGS
{

    public static final String APIPROP = "apiId"
    public static final String APITERATIONPROP = "iteration"
    public static final String OVERRIDEPROP = "override"
    public static final String PROPFILENAMEDEFAULT = 'tool.properties'
    public static final String LOGPOLICYTOFILE = 'logDebugPolicyToFile'
    
    public static final String IDCSPROP = "IDCS"
    public static final String TARGETIDCSPROP = "targetIDCS"
    public static final String SERVERPROP = "server"
    public static final String TARGETSERVERPROP = "targetServer"
    public static final String USERNAMEPROP = "username"
    public static final String TARGETUSERNAMEPROP = "targetUsername"
    public static final String SCOPEPROP = "scope"
    public static final String TARGETSCOPEPROP = "targetScope"
    public static final String DISPLAYPROP = "display"
    public static final String VIEWPROP = "view"
    public static final String VIEWBASIC = "display"
    public static final String VIEWSUMMARY = "summary"
    public static final String VIEWSUMMARYALL = "summary-all"

    public static final String YPROPVAL = "y"
    public static final String YESPROPVAL = "yes"
    public static final String TPROPVAL = "t"
    public static final String TRUEPROPVAL = "true"

}

String view = null
int apiId = 1
int apiIter = 0
boolean overrideTarget = false
debug = false // allows us to pretty print all the API calls if necessary
logDebugPolicyToFile = false

String propFilename = CONFIGS.PROPFILENAMEDEFAULT
Properties props = null
File propFile = null
ConfigObject config = null


class Source
{
    public String clientId = null
    public String clientSecret = null
    public String idcs = null
    public String scope = null

    public String uName = null
    public String password = null
    public String svr = null

    private String authString = null

    boolean usingIDCS()
    {
        return (idcs != null)
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
        String combi = clientId + ":" + clientSecret
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

Source inSource = new Source()
Source outSource = new Source()


HELP = "-h or -help -- provides this information\n" +
       "The following parameters are required on the command line:\n" +
       "  - inPass - password for the source management cloud\n" +
       "  - outPass - optional, the target management cloud password, only needed for migrations\n" +
       "  - inClientId - client identifier needed for IDCS\n" +
       "  - outClientId - (optional) client identifier needed for the target IDCS if different from the input\n" +
       "  - inClientSecret - client secret needed for IDCS\n" +
       "  - outClientSecret - (optional) client secret needed for the target IDCS if different from the input\n" +
       "\nThe following information is taken from the configuration file tool.properties:\n" +
       "  - policy - numeric identifier for the policy of interest\n" +
       "  - iter - iteration number of interest for the policy - optional\n" +
       "  - outName - optional, the target management cloud username, only needed for migrations\n" +
       "  - svr - the source management cloud server address - same formatting as inSvr, only needed for\n" +
       "  - targetSvr - optional, the target management cloud server address - same formatting as svr\n" +
       "  - IDCS - URL to the token service in IDCS e.g. https://idcs-xyz.identity.oraclecloud.com/oauth2/v1/token\n" +
       "  - targetIDCS - optional, the same as IDCS but for the target environment\n" +
       "  - scope - the scope information for the token being requested\n" +
       "  - targetScope - optional, only needed for a different target environment\n" +
       "  - username - user name to access the source\n" +
       "  - targetUsername - optional, user name to access the target if different\n" +
       "  - override - optional, if migrating to another management, tells the script to replace the existing policy of the samename if found\n" +
       "  - view (optional), separate command to allow viewing of the policy - requires one of the following value:\n" +
       "        - summary - provides the headline information of the policy including name, change date etc\n" +
       "        - summary-all - summarises all the iterations from the current one back to the 1st\n" +
       "  - display - optional, will get script to report more information about what is happening\n" +
       "  - logDebugPolicyToFile - as the policy JSON can be large, if display is enabled  then this can be used to " +
       "write the policies to file\n" +
       "see https://blog.mp3monster.org/category/technology/oracle/api-platform-cs/ for more info"


try
{

    if (args.size() > 0)
    {
        if (args[0] == "-h")
        {
            println("Help:\n" + HELP)
            System.exit(0)
        }
        else
        {
        }

        int argIdx = 0
        int sze = 0

        if (args != null)
        {
            sze = args.size()
        }
        while (argIdx < sze)
        {

            switch (args[argIdx])
            {

                case '-inPass':
                    inSource.password = args[argIdx + 1]
                    argIdx += 2

                    // if the password hasn't been set default it to match
                    if (outSource.password == null)
                    {
                        outSource.password = inSource.password;
                    }
                    break

                case '-outPass':
                    outSource.password = args[argIdx + 1]
                    argIdx += 2
                    break

                case '-inClientId':
                    inSource.clientId = args[argIdx + 1]
                    argIdx += 2

                    // if the password hasn't been set default it to match
                    if (outSource.clientId == null)
                    {
                        outSource.clientId = inSource.clientId
                    }
                    break

                case '-outClientId':
                    outSource.clientId = args[argIdx + 1]
                    argIdx += 2
                    break


                case '-inClientSecret':
                    inSource.clientSecret = args[argIdx + 1]
                    argIdx += 2

                    // if the password hasn't been set default it to match
                    if (outSource.clientSecret == null)
                    {
                        outSource.clientSecret = inSource.clientSecret
                    }
                    break

                case '-outClientSecret':
                    outSource.clientSecret = args[argIdx + 1]
                    argIdx += 2
                    break
            }
        }
    }
    else
    {
        println("No params found - exiting\n\n")
        println(HELP)
        System.exit(0)
    }


}
catch (Exception err)
{
    System.err.println("Error message:" + err.getMessage() + "\n\n")
    System.err.println(err.getStackTrace())
    println(HELP)
    System.exit(-1)
}

props = new Properties();
propFile = new File(propFilename);
props.load(propFile.newDataInputStream())
config = new ConfigSlurper().parse(props)

debug = getConfigState(config, CONFIGS.DISPLAYPROP, false)

if (debug)
{
    println("Loaded Properties")
}

inSource.svr = config.get(CONFIGS.SERVERPROP)
outSource.svr = config.get(CONFIGS.TARGETSERVERPROP)
if (outSource.svr == null)
{
    outSource.svr = inSource.svr
}

inSource.uName = config.get(CONFIGS.USERNAMEPROP)
outSource.uName = config.get(CONFIGS.TARGETUSERNAMEPROP)
if (outSource.uName == null)
{
    outSource.uName = inSource.uName
}

inSource.idcs = config.get(CONFIGS.IDCSPROP)
outSource.idcs = config.get(CONFIGS.TARGETIDCSPROP)
if (outSource.idcs == null)
{
    (outSource.idcs = inSource.idcs)
}

inSource.scope = config.get(CONFIGS.SCOPEPROP)
outSource.scope = config.get(CONFIGS.TARGETSCOPEPROP)
if (outSource.scope == null)
{
    outSource.scope = inSource.scope
}

overrideTarget = getConfigState(config, CONFIGS.OVERRIDEPROP, false)
logDebugPolicyToFile = getConfigState(config, CONFIGS.LOGPOLICYTOFILE, false)
println("logDebugPolicyToFile is set to " + logDebugPolicyToFile)

final int UNSET = -1
apiIter = getConfigNumber(config, CONFIGS.APITERATIONPROP, UNSET)

if (apiIter == UNSET)
{
    System.out.println("Couldn't process Iteration number\n")
    system.out.println(HELP)
    System.exit(0)
}

apiId = getConfigNumber(config, CONFIGS.APIPROP, UNSET)


view = config.get(CONFIGS.VIEWPROP)
if (view != null)
{
    view = view.trim().toLowerCase()

    if (!(view.equals(CONFIGS.VIEWBASIC) || view.equals(CONFIGS.VIEWSUMMARY) || view.equals(CONFIGS.VIEWSUMMARYALL)))
    {
        println("ignoring view setting of " + view)
        view = null
    }
}

if (debug)
{
    println("Configuration loaded")
}

// verify all the parameters
try
{
    inSource.applyAssertions("source")
    outSource.applyAssertions("target")
}

catch (AssertionError assertErr)
{
    println(assertErr.getMessage() + "\n\n")
    println("Parameters incomplete:" + HELP)
    System.exit(0)
}


if (debug)
{
    inSource.printConnection("Input")
    outSource.printConnection("Output")
    println("Configuration complete")
}


// certificate by pass ====================
// http://codingandmore.blogspot.co.uk/2011/07/json-and-ssl-in-groovy-how-to-ignore.html

class OverideHostnameVerifier implements HostnameVerifier
{
    boolean verify(String hostname, SSLSession session) { return true }
}

class TrustManager implements X509TrustManager
{

    public java.security.cert.X509Certificate[] getAcceptedIssuers()
    {
        return null;
    }

    public void checkClientTrusted(
            java.security.cert.X509Certificate[] certs, String authType)
    {
    }

    public void checkServerTrusted(
            java.security.cert.X509Certificate[] certs, String authType)
    {
    }
}

TrustManager[] trustAllCerts = new TrustManager[1]

trustAllCerts[0] = new TrustManager()


// as we need to process a number of config values the same way - this provides the standardised logic
boolean getConfigState(ConfigObject config, String property, boolean defaultVal)
{
    boolean set = defaultVal

    String valStr = config.get(property)
    if (valStr != null)
    {
        valStr = valStr.trim()

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
    if (debug)
    {
        println("Configuration for " + property + " is " + set)
    }

    return set
}

// as we need to process a number of config values the same way - this provides the standardised logic
int getConfigNumber(ConfigObject config, String property, int defaultVal)
{
    int set = defaultVal

    String valStr = config.get(property)
    if (valStr != null)
    {
        try
        {
            set = valStr.toInteger()
        }
        catch (Exception err)
        {
            // couldn't convert to numeric so will return default
            if (debug)
            {
                println("Couldnt convert " + valStr + " to a numeric for " + property)
            }
        }
    }

    return set
}


// look for the existence of a policy by name in the named instance
public boolean policyExistsInTarget(String policyName, String uname, String password, String svr,
                                    TrustManager[] trustAllCerts, SSLContext sc, boolean debug)
{
    // https://example.com/apiplatform/management/v1/apis/preview?fields=vanityName
    if (debug)
    {
        println("Checking in " + svr + " for " + policyName)
    }

    boolean matched = false

    // configure HTTP connectivity inc ignoring certificate validation
    HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
    HttpsURLConnection.setDefaultHostnameVerifier((HostnameVerifier) new OverideHostnameVerifier())

    // get the API list
    String resourcePath = "/apiplatform/management/v1/apis/preview?fields=vanityName"
    def connection = new URL(svr + resourcePath).openConnection()
    connection.setRequestProperty("Content-Type", "application/json")
    connection.setRequestProperty("Authorization", outSource.getAuthString())
    def jsonAPIDefn = new JsonSlurper().parse(connection.getInputStream())

    if (debug)
    {
        println("checking svr " + svr + " for " + policyName)
    }

    // loop through the list of API Names

    def int idx = 0

    // search the list of target policies to match for an existing name
    while ((idx < jsonAPIDefn.items.size()) && (!matched))
    {
        if (jsonAPIDefn.items[idx].name == policyName)
        {
            matched = true
            if (debug)
            {
                println("Found match in svr " + svr + "for " + policyName)
            }
        }
        idx++
    }
    return matched
}

// provides a function to display the policy information so we can do it consistently when presenting a summary view
public void displayPolicySummary(String name, String description, String version, String stateUpdatedAt, String state,
                                 String iterationId)
{
    println("Policy:" + name + "| Version:" + version + "| Updated at:" + stateUpdatedAt + "| State:" + state +
            "| Iteration:" + iterationId + "| Description:" + description)
}


// this takes the details to connect to an API platform and push the update object (a representation of the policy) by not differentiating
// between the mgmt cloud queried and the target then we can use this to migrate as easily as revert forward
// resource path is provided as it will depend upon the operation include the policy identifier or not
// isInsert tells us which verb will be required
public void pushPolicy(String resourcePath, String update, boolean isInsert, Source source, TrustManager[]
        trustAllCerts, SSLContext sc, boolean debug)
{
    // configure HTTP connectivity inc ignoring certificate validation
    sc.init(null, trustAllCerts, new java.security.SecureRandom())
    HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory())
    HttpsURLConnection.setDefaultHostnameVerifier((HostnameVerifier) new OverideHostnameVerifier())

    String method = 'PUT'
    if (!isInsert)
    {
        method = 'POST'
    }

    if (debug)
    {
        println("Target path:" + source.svr + resourcePath)
        println("Submitting:\n" + update)
        if (logDebugPolicyToFile)
        {
            def policyFile = new File('pushing-policy-definition.json').newOutputStream()
            policyFile.write(update.getBytes(), 0, update.size())
            policyFile.close()
        }

    }

    apiDefnUpdate = new URL(source.svr + resourcePath).openConnection()
    if (debug)
    {
        println("Calling " + " operation " + method + " on " + source.svr + resourcePath)
    }

    apiDefnUpdate.setRequestProperty("Authorization", source.getAuthString())
    apiDefnUpdate.setRequestProperty("Content-Type", "application/json")
    apiDefnUpdate.setDoOutput(true)
    apiDefnUpdate.setRequestMethod(method)
    apiDefnUpdate.setRequestProperty('User-agent', 'groovy script')

    // retrieve the response
    def out = new OutputStreamWriter(apiDefnUpdate.outputStream)
    out.write(update)
    out.close()

    if (debug)
    {
        String responseIn
        try
        {
            responseIn = apiDefnUpdate.getInputStream().getText()
            println("input " + responseIn)
        }
        catch (Exception err)
        {
            responseIn = "could retrieve a response detail"
        }
        println("Update response:" + apiDefnUpdate.responseCode + " : " + apiDefnUpdate.responseMessage + "\n"
                        + responseIn)
    }

}


// this cleans up the policy removing any elements identified as not required. What is retained is dictated
// by the rootRetainElements list
public Object cleanPolicy(Object jsonPolicy)
{
    // list of root elements needing to be carried from the lookup to the insert / update
    ArrayList rootRetainElements = new ArrayList()
    rootRetainElements.add("name")
    rootRetainElements.add("version")
    rootRetainElements.add("implementation")
//rootRetainElements.add("details")

    Object responseObj = jsonPolicy

    ArrayList removalList = new ArrayList()

    // look through the elements and identify what can be removed
    responseObj.keySet().each {
        if (!(rootRetainElements.contains(it)))
        {
            removalList.add(it)
            if (debug)
            {
                println("Identified for removal: " + it)
            }
        }
    }

    // loop through the removal list and take them out of the source JSON
    removalList.each
            {
                responseObj.remove(it)
                if (debug)
                {
                    println("removing " + it)
                }
    }

    return responseObj

}

// this function will pull down the policy object from the management cloud providing a slurped JSON object
// requires the policy numeric Id, the iteration - if the iteration is 0 then we get the latest iteration of the policy
// plus credentials to connect to the server
public Object getPolicy(int apiId, int apiIter, Source source, TrustManager[] trustAllCerts, SSLContext sc,
                        boolean debug)
{
    // configure HTTP connectivity inc ignoring certificate validation
    sc.init(null, trustAllCerts, new java.security.SecureRandom())
    HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory())
    HttpsURLConnection.setDefaultHostnameVerifier((HostnameVerifier) new OverideHostnameVerifier())


    // get the API policy
    String resourcePath = "/apiplatform/management/v1/apis/" + apiId
    if (apiIter > 0)
    {
        // if we're after a specific iteration then add it to the path, otherwise we default to the latest iteration
        resourcePath = resourcePath + "/iterations/" + apiIter
    }

    if (debug)
    {
        println("retrieving:" + source.svr + resourcePath)

    }
    def apiDefn = new URL(source.svr + resourcePath).openConnection()
    apiDefn.setRequestProperty('Authorization', source.getAuthString())

    def jsonAPIDefn = new JsonSlurper().parse(apiDefn.getInputStream())
    if (debug)
    {
        String output = new JsonBuilder(jsonAPIDefn).toPrettyString()
        if (logDebugPolicyToFile)
        {
            def policyFile = new File('pulled-policy-definition.json').newOutputStream()
            policyFile.write(output.getBytes(), 0, output.size())
            policyFile.close()
            println("write outputfile")
        }
        else
        {
            println("received definition:\n" + output)
        }
    }
    return jsonAPIDefn
}

// main

try
{
    if (debug)
    {
        println("Starting core process")
    }

    // create a context to work with
    SSLContext sc = SSLContext.getInstance('SSL')

    def jsonAPIDefn = getPolicy(apiId, apiIter, inSource, trustAllCerts, sc, debug)


    //if the action is just to view then exit NOW
    if (view != null)
    {
        if (view == "display") // display the entire policy
        {
            println(new JsonBuilder(jsonAPIDefn).toPrettyString())
        }
        else if (view == 'summary') // display the policy summary
        {
            displayPolicySummary(jsonAPIDefn.name, jsonAPIDefn.details.description, jsonAPIDefn.version,
                                 jsonAPIDefn.stateUpdatedAt, jsonAPIDefn.state, jsonAPIDefn.iterationId)
        }
        else if (view == 'summary-all')
        {
            // loop through all iterations printing the summary
            int iterLoop = jsonAPIDefn.iterationId.toInteger()
            iterLoop -= 1

            displayPolicySummary(jsonAPIDefn.name, jsonAPIDefn.details.description, jsonAPIDefn.version,
                                 jsonAPIDefn.stateUpdatedAt, jsonAPIDefn.state, jsonAPIDefn.iterationId)

            // loop through all the iterations from the current one going back and get the summary view
            while (iterLoop > 0)
            {
                jsonAPIDefn = getPolicy(apiId, iterLoop, inSource, trustAllCerts, sc, debug)
                displayPolicySummary(jsonAPIDefn.name, jsonAPIDefn.details.description, jsonAPIDefn.version,
                                     jsonAPIDefn.stateUpdatedAt, jsonAPIDefn.state, jsonAPIDefn.iterationId)
                iterLoop -= 1
            }

        }
    }
    else
    {

        // modify the policy description
        if (jsonAPIDefn.details != null)
        {
            if (jsonAPIDefn.details.description != null)
            {
                jsonAPIDefn.details.description = "Been subject to a reversion script " + jsonAPIDefn.details.description
            }
            else
            {
                jsonAPIDefn.details.description = "Been subject to a reversion script "
            }
        }

        jsonAPIDefn = cleanPolicy(jsonAPIDefn)


        boolean isInsert = true
        // set the path for the update
        if (inSource.svr == outSource.svr)
        {
            // we're working with the same API - so it exists
            if (debug)
            {
                println("reverting forward")
            }
            resourcePath = "/apiplatform/management/v1/apis/" + apiId
            isInsert = true

            if (jsonAPIDefn.details != null)
            {
                if (jsonAPIDefn.details.description != null)
                {
                    jsonAPIDefn.details.description += ' apply reversion to iteration ' + apiIter
                }
            }
        }
        else
        {
            // assume we're migrating from one server to another
            if (debug)
            {
                println("migrating")
            }

            resourcePath = "/apiplatform/management/v1/apis/" + apiId
            isInsert = false

            //test to see if already exists in target
            if (policyExistsInTarget(jsonAPIDefn.name, outSource, trustAllCerts, sc, debug))
            {
                println("confirmed match")
            }

            // have we got a entry already in the target environment and are we allowed to override it?
            if (overrideTarget && matched)
            {
                isInsert = false
            }
            else
            {
                // report conflict and exit process
                println("Found " + jsonAPIDefn.name + " exists in " + outSource.svr + " aborting")
                System.exit(0)
            }
            jsonAPIDefn.details.description += ' was iteration ' + apiIter + " on API Platform " + inSource.svr
        }
        pushPolicy(resourcePath, (new JsonBuilder(jsonAPIDefn).toPrettyString()), isInsert, outSource, trustAllCerts,
                   sc, debug);

    }
}
catch (Exception err)
{
    System.out.println(err.printStackTrace())
    println("Error:" + err.getMessage())
    println(HELP)
    System.exit(0)
}

import groovy.json.*
import java.net.URLConnection
import javax.net.ssl.*

// if defaults are set then calling with the default values will attempted
def String uname = null
def String password = null
def String svr = null
def boolean displayAll = false // allows us to pretty print all the API calls if necessary
def String clientId = null;
def String clientSecret = null;
def String scope = null; // IDCS scope
def String idcs = null; // URL for IDCS
def boolean useIDCS = false;

def String authString = null;

final AUTHORIZATION = "Authorization"

final String YPROPVAL = "y"
final String YESPROPVAL = "yes"
final String TPROPVAL = "t"
final String TRUEPROPVAL = "true"

final String IDCSPROP = "IDCS"
final String SERVERPROP = "server"
final String USERNAMEPROP = "username"
final String SCOPEPROP = "scope"
final String PROPFILENAME = 'tool.properties'
final String DISPLAYPROP = "display"


def final String HELP = "for help use -h\nExpected parameters for:\n" +
        "- Password/n" +
        "- client Id - if using IDCS\n" +
        "- client secret - if using IDCS\n" +
        "properties file tools.properties with values for:\n" +
        "- " + SERVERPROP + " API Platform server address\n" +
        "- " + USERNAMEPROP + " username for API Platform\n" +
        "- " + IDCSPROP + " - URL for OAuth token service\n" +
        "- " + SCOPEPROP + " scope string for IDCS to use" +
        "- " + DISPLAYPROP + " optional - indicates whether to display all the information gathered to build report\n" +
        "Documentation is at https://blog.mp3monster.org/2018/01/25/understanding-api-deployment-state-on-api-platform/"


if (args.size() > 0)
{
    if (args[0] == "-h")
    {
        println(HELP)
        System.exit(0);
    } else
    {
        try
        {
            password = args[0]

            if (args.size() > 1)
            {
                clientId = args[1]
                clientSecret = args[2]
            }

        }
        catch (Exception err)
        {
            System.out.println("Error handling arguments")
            System.out.println(HELP)
            System.exit(0)
        }
    }
} else
{
    System.out.println(HELP)
    System.exit(0)
}

def props = new Properties();
File propFile = new File(PROPFILENAME);
props.load(propFile.newDataInputStream())
def config = new ConfigSlurper().parse(props)

uname = config.get(USERNAMEPROP)
svr = config.get(SERVERPROP)
svr = svr.trim()

idcs = config.get(IDCSPROP)
scope = config.get(SCOPEPROP)
useIDCS = ((idcs != null) && (idcs.size() > 0))


def displayStr = config.get(DISPLAYPROP)
displayAll = false
if ((displayStr != null) && (displayStr.equalsIgnoreCase(YPROPVAL) ||
        displayStr.equalsIgnoreCase(YESPROPVAL) ||
        displayStr.equalsIgnoreCase(TPROPVAL) ||
        displayStr.equalsIgnoreCase(TRUEPROPVAL)))
{
    displayAll = true;
    println("Setting display all on")
}

// verify all the parameters
try
{
    assert ((uname != null) && (uname.size() > 0)): "No username"
    assert ((password != null) && (password.size() > 0)): "No password"
    assert ((svr != null) && (svr.size() > 0)): "No server"

    if (useIDCS)
    {
        println("checking idcs")
        assert ((scope != null) && (scope.size() > 0)): "Scope not defined"
        assert ((clientId != null) && (clientId.size() > 0)): "Client Id not defined"
        assert ((clientSecret != null) && (clientSecret.size() > 0)): "Client Secret not defined"
    }
}
catch (AssertionError assertErr)
{
    System.out.println(assertErr.getMessage())
    System.out.println(HELP)
    System.exit(0)
}

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


public String getAccessToken(String idcs, String clientId, String clientSecret, String userName, String password, String scope)
{
    final String ENC = "UTF-8";
    String accessToken = null;
    String combi = clientId + ":" + clientSecret;
    String authHeader = "Basic " + Base64.getEncoder().encodeToString(combi.getBytes());

    try
    {
        URL url = new URL(idcs);
        HttpsURLConnection con = (HttpsURLConnection) url.openConnection();
        con.setRequestMethod("POST");
        con.setRequestProperty("AUTHORIZATION", authHeader);
        con.setRequestProperty("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8");
        con.setRequestProperty("Accept", "application/json");
        con.setDoOutput(true);

        try
        {
            PrintStream os = new PrintStream(con.getOutputStream());

            StringBuilder sb = new StringBuilder("grant_type=password&username=");
            sb.append(URLEncoder.encode(userName, ENC));

            sb.append("&scope=");
            sb.append(URLEncoder.encode(scope, ENC));

            sb.append("&password=");
            sb.append(URLEncoder.encode(password, ENC));

            os.print(sb.toString());
            os.close();
        }
        catch (Exception err)
        {
            System.out.println("error trying to produce URL\n" + err.getMessage());
        }

        if (con.getResponseCode() == HttpURLConnection.HTTP_OK)
        {
            BufferedReader reader = new BufferedReader(new InputStreamReader(con.getInputStream()));
            String line;
            StringBuilder access = new StringBuilder();
            while ((line = reader.readLine()) != null)
            {
                access.append(line);
            }

            def json = new JsonSlurper().parseText(access.toString());
            accessToken = json.access_token;
        } else
        {
            throw new Exception("Oh crap - that didn't go very well -- response = " + con.getResponseCode());
        }
    }
    catch (Exception err)
    {
        System.err.println("Err getting token:\n" + err.getMessage());
    }

    return accessToken;
}


// main


try
{
    // configure HTTP connectivity inc ignoring certificate validation
    SSLContext sc = SSLContext.getInstance("SSL");
    sc.init(null, trustAllCerts, new java.security.SecureRandom());
    HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
    HttpsURLConnection.setDefaultHostnameVerifier((HostnameVerifier) new OverideHostnameVerifier());

    if (useIDCS)
    {
        authString = "Bearer " + getAccessToken(idcs, clientId, clientSecret, uname, password, scope)
    } else
    {
        // setup password string
        final String authStringPlain = uname + ":" + password
        authString = "Basic " + (authStringPlain.getBytes().encodeBase64().toString())
    }

    String url = svr + "/apiplatform/management/v1/apis"
    if (displayAll)
    {
        println("URL:" + url)
    }
    // list all APIs
    def callAPIsList = new URL(url).openConnection()
    callAPIsList.setRequestProperty(AUTHORIZATION, authString)
    def jsonAPIList = new JsonSlurper().parse(callAPIsList.getInputStream())
    if (displayAll)
    {
        println("Result back is null=" + (jsonAPIList == null))
        println(new JsonBuilder(jsonAPIList).toPrettyString())
    }


    // build list of gateway ids vs gateway names
    HashMap gatewayLookup = new HashMap()
    def callGatewayListURI = new URL(svr + "/apiplatform/management/v1/gateways").openConnection()
    callGatewayListURI.setRequestProperty(AUTHORIZATION, authString)
    def jsonGWayDesc = new JsonSlurper().parse(callGatewayListURI.getInputStream())
    for (gwIdx = 0; gwIdx < jsonGWayDesc.items.size(); gwIdx++)
    {
        gatewayLookup.put(jsonGWayDesc.items[gwIdx].id, jsonGWayDesc.items[gwIdx].name)
        if (displayAll)
        {
            println(jsonGWayDesc.items[gwIdx].id + ":" + jsonGWayDesc.items[gwIdx].name)
        }
    }

    // get count of APIs to process
    def apiCount = jsonAPIList.items.size()

    // loop over all the APIs
    for (idx = 0; idx < apiCount; idx++)
    {
        // Examine each API +++++++++++++++
        String id = jsonAPIList.items[idx].id;
        println("\n")

        def callAPI = new URL(svr + "/apiplatform/management/v1/apis/" + id).openConnection()
        callAPI.setRequestProperty(AUTHORIZATION, authString)
        def jsonAPIDesc = new JsonSlurper().parse(callAPI.getInputStream())

        if (displayAll)
        {
            println(new JsonBuilder(jsonAPIDesc).toPrettyString())
        }
        def dispName = jsonAPIDesc.name
        if (dispName == null)
        {
            dispName = "<name not defined!>"
        }
        println("name=" + dispName + "|id=" + jsonAPIDesc.id + "|ver=" + jsonAPIDesc.version + "|latest iteration=" + jsonAPIDesc.iterationId);

        if (displayAll)
        {
            println(new JsonBuilder(jsonAPIDesc).toPrettyString());
        }
        // Examine each API --------------

        // Examine each API Deployment +++++++++++++++

        String callAPIDeployGwaysURI = svr + "/apiplatform/management/v1/apis/" + id + "/deployments?fields=api.iterationId,gateway.description"
        def callAPIDeployGways = new URL(callAPIDeployGwaysURI).openConnection()
        callAPIDeployGways.setRequestProperty(AUTHORIZATION, authString);

        def deployInfo = new JsonSlurper().parse(callAPIDeployGways.getInputStream())

        if (displayAll)
        {
            println("deployment info for " + id + " " + callAPIDeployGwaysURI)
            println(new JsonBuilder(deployInfo).toPrettyString())
        }

        if (deployInfo.items.size() > 0)
        {
            for (deployInfoIdx = 0; deployInfoIdx < deployInfo.items.size(); deployInfoIdx++)
            {
                final String defaultGWName = "<undefined name>";
                final String defaultGwayId = "-"
                def dispGWayName = defaultGWName;
                def dispGwayId = defaultGwayId;
                String iterId = ""

                // if version of mgmt cloud then ...
                dispGWayName = gatewayLookup.get(deployInfo.items[deployInfoIdx].gateway.id)
                dispGwayId = deployInfo.items[deployInfoIdx].gateway.id

                String callAPIDeployIdURI = svr + "/apiplatform/management/v1/apis/" + jsonAPIDesc.id + "/deployments/" + deployInfo.items[deployInfoIdx].id + "/api"
                if (displayAll)
                {
                    println(callAPIDeployIdURI)
                }

                def callAPIDeployId = new URL(callAPIDeployIdURI).openConnection()
                callAPIDeployId.setRequestProperty(AUTHORIZATION, authString);
                def deployIdInfo = new JsonSlurper().parse(callAPIDeployId.getInputStream())

                if (displayAll)
                {
                    println("deployment info for " + id + "/" + deployInfo.items[deployInfoIdx].id + " " + callAPIDeployIdURI)
                    println(new JsonBuilder(deployIdInfo).toPrettyString())
                }

                iterId = deployIdInfo.iterationId


                if ((dispGWayName != defaultGWName) && (dispGwayId != defaultGwayId))
                {
                    println("iteration=" + iterId + "| " +
                            "gateway=" + dispGWayName + "(" + dispGwayId + ")")
                }

            }
        }
    } // for

}
catch (Exception err)
{
    err.printStackTrace()
    System.out.println(err.getMessage())
    System.out.println(HELP)
}

import groovy.json.*
import java.net.URLConnection
import javax.net.ssl.*

// if defaults are set then calling with the default values will attempted
def String uname = null;
def String password = null;
def String svr = null;
def boolean displayAll = true // allows us to pretty print all the API calls if necessary
def boolean displayDetailed = false;
def String clientSecret = null;
def String clientId = null;
def String IDCSURI = null;
def String scope = null;
def boolean useIDCS = false;
def String nudgeRecipient = null;
def String nudgeChannel = null;
def String nudgeToken = null;

def String authString = null; // hold the authorization string used in the different connnections

final String YPROPVAL = "y";
final String YESPROPVAL = "yes";
final String TPROPVAL = "t";
final String TRUEPROPVAL = "true";

final String TOKEN = "token";
final String CHANNEL = "channel";
final String WHO = "who";
final String IDCSPROP = "IDCS";
final String SERVERPROP = "server";
final String USERNAMEPROP = "username";
final String SCOPEPROP = "scope";
final String PROPFILENAME = 'tool.properties';
final String DISPLAYPROP = "display";
final String DISPLAYPROPDETAILOPT = "detail";
final String NOMATCH = "-1";
final String HELPMSG = "requires " + PROPFILENAME + " file to be in the same location as the script\n " +
                       "parameters are:\nPassword -- for API Management or IDCS\n" +
                       "Client Id for IDCS based access\nClient Secret for IDCS access" +
                       "\n Properties file needs to include - " + DISPLAYPROP + "\n" + USERNAMEPROP + "\n" + SCOPEPROP + "\n" +
                       SERVERPROP + "\n" + IDCSPROP + "\n" + CHANNEL;
                       
AUTHORIZATION = "Authorization";
CONTENT = "Content-Type";
JSON = "application/json; charset=utf-8";
ACCEPT = "Accept";

def props = new Properties();
File propFile = new File(PROPFILENAME);
props.load(propFile.newDataInputStream());
def config = new ConfigSlurper().parse(props);

nudgeChannel = config.get(CHANNEL);
nudgeRecipient = config.get(WHO);
nudgeToken = config.get(TOKEN);

def displayStr = config.get(DISPLAYPROP);
displayAll = false
displayDetailed = false
if ((displayStr != null) && (displayStr.equalsIgnoreCase(YPROPVAL) ||
                             displayStr.equalsIgnoreCase(YESPROPVAL) ||
                             displayStr.equalsIgnoreCase(TPROPVAL) ||
                             displayStr.equalsIgnoreCase(TRUEPROPVAL)))
{
    displayAll = true;
    displayDetailed = false
}
else if ((displayStr != null) && (displayStr.equalsIgnoreCase(DISPLAYPROPDETAILOPT)))
{
    displayAll = true
    displayDetailed = true
}

uname = config.get(USERNAMEPROP)
svr = config.get(SERVERPROP)
svr = svr.trim();
IDCSURI = config.get(IDCSPROP)
IDCSURI = IDCSURI.trim()
useIDCS = ((IDCSURI != null) && (IDCSURI.size() > 0))
scope = config.get(SCOPEPROP)

int argIdx = 0;
if (args.size() > 0)
{
    if (args[0].equals("-h"))
    {
        // display the help info
        System.out.println(HELPMSG)
        System.exit(0)
    }
    else
    {
        // try process the params
        try
        {
            password = args[argIdx];
            argIdx++;

            if (useIDCS)
            {
                clientId = args[argIdx];
                argIdx++;
                clientSecret = args[argIdx];
                argIdx++;
            }

            if (args.size() == argIdx)
            {
                nudgeToken=args[argIdx];
            }

        }
        catch (Exception err)
        {
            System.out.println("error processing command line")
        }
    }
}

// verify all the parameters
try
{

    if (useIDCS)
    {
        assert (clientId != null && clientId.size() > 0): "No client id"
        assert (clientSecret != null && clientSecret.size() > 0): "No client secret"
        assert (IDCSURI != null && IDCSURI.size() > 0): "No URL for IDCS"
        assert (scope != null && scope.size() > 0): "No scope"
    }
    else
    {
        assert ((uname != null) && (uname.size() > 0)): "No username"
        assert ((password != null) && (password.size() > 0)): "No password"
    }
    assert ((svr != null) && (svr.size() > 0)): "No Server"
    assert ((nudgeToken!= null) && (nudgeToken.size() > 0)): "No token for slack";
    assert ((nudgeChannel!= null) && (nudgeChannel.size() > 0)): "No channel for slack";

}
catch (AssertionError err)
{
    System.out.println(err.getMessage())
    System.out.println("---- use -h to get details of expected")
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


public String getAccessToken(String idcs, String clientId, String clientSecret, String userName, String password,
                             String scope)
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
        con.setRequestProperty(AUTHORIZATION, authHeader);
        con.setRequestProperty(CONTENT, "application/x-www-form-urlencoded; charset=UTF-8");
        con.setRequestProperty(ACCEPT, JSON);
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
        }
        else
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


TrustManager[] trustAllCerts = new TrustManager[1]
trustAllCerts[0] = new TrustManager()


// main
String nudgeStr = "";
int requestCount = 0;

try
{
    // configure HTTP connectivity inc ignoring certificate validation
    SSLContext sc = SSLContext.getInstance("SSL");
    sc.init(null, trustAllCerts, new java.security.SecureRandom());
    HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
    HttpsURLConnection.setDefaultHostnameVerifier((HostnameVerifier) new OverideHostnameVerifier());

    def getAPIs = new URL(svr + "/apiplatform/management/v1/apis").openConnection();


    if (useIDCS)
    {
        authString = "Bearer " + getAccessToken(IDCSURI, clientId, clientSecret, uname, password, scope);
    }
    else
    {
        // setup password string
        final String authStringPlain = uname + ":" + password;
        authString = "Basic " + (authStringPlain.getBytes().encodeBase64().toString());

    }

    getAPIs.setRequestProperty(AUTHORIZATION, authString);
    getAPIs.setRequestMethod("GET");
    getAPIs.setDoOutput(true);
    getAPIs.setRequestProperty(ACCEPT, JSON);    

    // solution Logic.

    def APIList = new JsonSlurper().parse(getAPIs.getInputStream())
    if (displayDetailed)
    {
        println(new JsonBuilder(APIList).toPrettyString())
    }

    // get count of gateways to process
    def APICount = APIList.items.size()

    // loop over all the APIs
    for (idx = 0; idx < APICount; idx++)
    {
        def apiDeploy = new URL(svr + "/apiplatform/management/v1/apis/" + APIList.items[idx].id+"/deployments").openConnection();
        apiDeploy.setRequestProperty(AUTHORIZATION, authString);
        apiDeploy.setRequestMethod("GET");
        apiDeploy.setDoOutput(true);
        apiDeploy.setRequestProperty(ACCEPT, JSON);  

        def APIDeployDetail = new JsonSlurper().parse(apiDeploy.getInputStream())
        int deployCount = APIDeployDetail.count;
        if (displayAll)
        {
            println("name=" + APIList.items[idx].name + " (id=" + APIList.items[idx].id+") deploy count="+deployCount);

            if (displayDetailed)
            {
                println(new JsonBuilder(APIDeployDetail).toPrettyString());
            }
        }

        if (deployCount > 0)
        {
            for (deployIdx=0; deployIdx < deployCount; deployIdx++)
            {
                if (displayAll)
                {
                    println("State=" + APIDeployDetail.items[deployIdx].deploymentState);
                }

                if (APIDeployDetail.items[deployIdx].deploymentState.equalsIgnoreCase("REQUESTING"))
                {
                    requestCount++;
                    nudgeStr = nudgeStr + "\n" + APIList.items[idx].name;
                }
            }
        }
    } //loop on APIs

    

    if (requestCount > 0)
    {

        // prove we can nudge Slack
        // api needed : https://api.slack.com/methods/chat.meMessage
        // post to : https://slack.com/api/chat.meMessage
        // content : application/json
        // test with https://api.slack.com/methods/chat.meMessage/test
        // API to get status info that dictates a nudge requirement:
        // https://docs.oracle.com/en/cloud/paas/api-platform-cloud/apfrm/op-apis-apiid-deployments-depid-get.html
        // note for reasons unclear - Slack doesn't seem to process any provided body content

        if (nudgeStr.size() > 100)
        {
            nudgeStr = nudgeStr.substring (0, 100) + "...";
        }

        nudgeStr = "Pending requests (" + requestCount + ")" + nudgeStr;

        if ((nudgeRecipient != null) || (nudgeRecipient.size() > 0))
        {
            nudgeStr = nudgeRecipient + "\n" + nudgeStr;
        }

        String nudgeStrEncoded=java.net.URLEncoder.encode(nudgeStr, "UTF-8");

        def nudge = new URL("https://slack.com/api/chat.meMessage?token="+nudgeToken+"&channel="+nudgeChannel+"&text="+nudgeStrEncoded).openConnection();
        nudge.setRequestMethod("POST");
        nudge.setDoOutput(true);
        nudge.setDoInput(true);
        nudge.setRequestProperty(CONTENT, JSON); 
        nudge.setRequestProperty(ACCEPT, JSON);    
        nudge.outputStream.withWriter { writer ->writer << nudgeStr}

            def respCode = nudge.getResponseCode();

            if (displayAll)
            {
                System.out.println (respCode + " for ==>" + nudgeStr);
            }

        if (respCode != 200)
        {
            println (nudge.inputStream.withReader { Reader reader -> reader.text });
        }
    }

}
catch (Exception err)
{
    err.printStackTrace()
    println(err.getMessage())
    println(HELPMSG)
}
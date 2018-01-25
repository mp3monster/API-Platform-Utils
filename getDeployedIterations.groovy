import groovy.json.*
import java.net.URLConnection
import javax.net.ssl.*

// if defaults are set then calling with the default values will attempted
def String uname = "weblogic"
def String password = "Welcome1"
def String svr = "https://1.2.3.4"
def boolean displayAll = false // allows us to pretty print all the API calls if necessary

if (args.size() > 0)
{
    try
    {
    svr = args [0]
    uname = args[1]
    password = args [2]

    }
    catch (Exception e)
    {
        println ("Expect server username password")
         System.exit(0)
    }
}
else
{
    println ("Going to try with defaults in script")
}

// verify all the parameters
try
{
    assert (uname.size() > 0) : "No username"
    assert (password.size() > 0) : "No password"
    assert (svr.size() > 0) : "No server"
}
catch (AssertionError e)
{
     println (e.getMessage())
     println ("Expect server username password")
     System.exit(0)
}

// certificate by pass ====================
// http://codingandmore.blogspot.co.uk/2011/07/json-and-ssl-in-groovy-how-to-ignore.html

class OverideHostnameVerifier implements HostnameVerifier {
boolean verify(String hostname,
             SSLSession session)
             {return true}
}

class TrustManager implements X509TrustManager {

    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
    return null;
    }

    public void checkClientTrusted(
    java.security.cert.X509Certificate[] certs, String authType) {
    }

    public void checkServerTrusted(
    java.security.cert.X509Certificate[] certs, String authType) {
    }

}

TrustManager[] trustAllCerts = new TrustManager[1]

trustAllCerts[0] = new TrustManager()


 // main


try {
        // configure HTTP connectivity inc ignoring certificate validation
        SSLContext sc = SSLContext.getInstance("SSL");
        sc.init(null, trustAllCerts, new java.security.SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
        HttpsURLConnection.setDefaultHostnameVerifier((HostnameVerifier)new OverideHostnameVerifier());

        // setup password string
        final String authStringPlain = uname+":"+password
        final authString = "Basic " + (authStringPlain.getBytes().encodeBase64().toString())
        final String Authorization = "Authorization"

        // list all APIs
        def callAPIsList = new URL(svr+"/apiplatform/management/v1/apis").openConnection()
        callAPIsList.setRequestProperty(Authorization, authString)
        def jsonAPIList = new JsonSlurper().parse(callAPIsList.getInputStream())
        if (displayAll) { println (new JsonBuilder(jsonAPIList).toPrettyString()) }

        // get count of APIs to process
        def apiCount = jsonAPIList.items.size()

        // loop over all the APIs
        for (idx=0; idx < apiCount; idx++)
        {
            // Examine each API +++++++++++++++
            String id = jsonAPIList.items[idx].id;
            println ("")
            println ("")

            def callAPI = new URL(svr+"/apiplatform/management/v1/apis/" + id+"/preview").openConnection()
            callAPI.setRequestProperty(Authorization, authString)
            def jsonAPIDesc = new JsonSlurper().parse(callAPI.getInputStream())

            println ("name=" + jsonAPIDesc.name + "|id="+ jsonAPIDesc.id + "|ver="+jsonAPIDesc.version);
            if (displayAll)
            {
                println (new JsonBuilder(jsonAPIDesc).toPrettyString());
            }
            // Examine each API --------------

            // Examine each API Deployment +++++++++++++++

            def callAPIDeployGways = new URL(svr+"/apiplatform/management/v1/apis/" + id+"/deployments?fields=api.iterationId").openConnection()
            callAPIDeployGways.setRequestProperty(Authorization, authString);

            def deployInfo = new JsonSlurper().parse(callAPIDeployGways.getInputStream())

                if (displayAll)
                {
                    println (new JsonBuilder(deployInfo).toPrettyString())
                }

            if (deployInfo.items.size() > 0)
            {
                for (deployInfoIdx = 0; deployInfoIdx <deployInfo.items.size(); deployInfoIdx++)
                {
                    println(//"name=" + deployInfo.items[deployInfoIdx].api.name +
                        //"|id="+ deployInfo.items[deployInfoIdx].api.id +
                        "|iteration="+deployInfo.items[deployInfoIdx].api.iterationId +
                        "| gateway="+deployInfo.items[deployInfoIdx].gateway.name +
                        "(" + deployInfo.items[deployInfoIdx].gateway.id+")")
                }
            }
    }

} catch (Exception e) {
    e.printStackTrace()
}

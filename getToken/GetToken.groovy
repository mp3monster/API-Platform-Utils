import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import javax.net.ssl.HttpsURLConnection;
import java.util.Base64;
import groovy.json.*

final String IDCSPROPERTY = "idcs"
final String USERNAMEPROPERTY = "username"
final String SCOPEPROPERTY = "scope"
final String OUTFILEPROPERTY = "output-file"
final String PROPFILENAME = 'config.properties'

final HELP = "For help use the parameter -h\n\nThe following values are required in the parameters:\n" +
             " - user password\n" +
             " - client Id\n" +
             " - client secret\n" +
             "Uses local file called " + PROPFILENAME + " to retrieve configuration for:\n" +
             " - " + SCOPEPROPERTY + "\n" +
             " - " + IDCSPROPERTY + "\n" +
             " - " + USERNAMEPROPERTY + "\n" +
             " - " + OUTFILEPROPERTY + "\n"  +
             "more at blog.mp3monster.org"

Properties props = null
File propFile = null
ConfigObject config = null

try
{
    props = new Properties()
    propFile = new File(PROPFILENAME)
    props.load(propFile.newDataInputStream())
    config = new ConfigSlurper().parse(props)
}
catch (Exception err)
{
    System.out.println(err.getMessage())
    System.out.println(HELP)
    System.exit(-1)
}

String username = config.get(USERNAMEPROPERTY)
String idcs = config.get(IDCSPROPERTY)
String scope = config.get(SCOPEPROPERTY)
String outFile = config.get(OUTFILEPROPERTY)

try
{
    if (args.size() > 0)
    {
        if (args[0].equalsIgnoreCase("-h"))
        {
            System.out.println(HELP)
            System.exit(0)
        }
        else
        {
            password = args[0]
            clientId = args[1]
            clientSecret = args[2]
        }
    }
    else
    {
        System.out.println("Problem with the parameters provided")
        System.out.println(HELP)
        System.exit(-1)
    }

    assert ((password != null) && password.size() > 0): "Password not properly configured"
    assert ((idcs != null) && idcs.size() > 0): "IDCS OAuth Token service location not configured"
    assert ((clientId != null) && clientId.size() > 0): "Client Id not provided"
    assert ((clientSecret != null) && clientSecret.size() > 0): "Client Secret not provided"
    assert ((username != null) && username.size() > 0): "username not configured"
    assert ((scope != null) && scope.size() > 0): "scope not configured"


    String token = getToken(idcs, clientId, clientSecret, username, password, scope)

    if ((outFile != null) && (outFile.size() > 0))
    {
        BufferedWriter writer = new BufferedWriter(new FileWriter(outFile))
        writer.write(token)

        writer.close()

        println("Wrote token to " + outFile)
    }
    else
    {
        println("Token acquired:\n" + token)
    }

}
catch (Exception err)
{
    System.out.println(err.getMessage())
    System.out.println(HELP)
    System.exit(-1)

}

// idcs - the URL of the IDCS server e.g. https://idcs-xxxx.identity.oraclecloud.com/oauth2/v1/token
// clientId - aaaa -- can be located in the UI
// client secret bbbb -- can be located in the UI
// user name 
// password
// scope "https://yyyyy.apiplatform.ocp.oraclecloud.com:443.apiplatform offline_access"
public static String getToken(String idcs, String clientId, String clientSecret, String userName, String password, String scope)
{
    final String ENC = "UTF-8"
    String accessToken = null
    String combi = clientId + ":" + clientSecret
    String authHeader = "Basic " + Base64.getEncoder().encodeToString(combi.getBytes())

    try
    {
        URL url = new URL(idcs)
        HttpsURLConnection con = (HttpsURLConnection) url.openConnection()
        con.setRequestMethod("POST")
        con.setRequestProperty("Authorization", authHeader)
        con.setRequestProperty("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
        con.setRequestProperty("Accept", "application/json")
        con.setDoOutput(true);

        System.out.println("Connection built to " + idcs)

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
            String line = null
            StringBuilder access = new StringBuilder();
            while ((line = reader.readLine()) != null)
            {
                access.append(line);
            }
            def json = new JsonSlurper().parseText(access.toString())

            //println (new JsonBuilder(json).toPrettyString())

            accessToken = json.access_token
        }
        else
        {
            throw new Exception("Something went wrong -- response = " + con.getResponseCode())
        }
    }
    catch (Exception err)
    {
        System.err.println(err.getMessage())
        //System.out.println (HELP)
    }
    return accessToken;
}


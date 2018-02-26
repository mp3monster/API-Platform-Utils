import groovy.json.*
import java.net.URLConnection
import javax.net.ssl.*
import groovy.json.JsonBuilder

// variables to hold configuration parameters
def String view = null;
def String inUName = null
def String outUName = null
def String inPassword = null
def String outPassword = null
def String inSvr = null
def String outSvr = inSvr
def int apiId = 1;
def int apiIter = 0;
def boolean overrideTarget = false;
boolean displayAll = false // allows us to pretty print all the API calls if necessary

// list of root elements needing to be carried from trhe lookup to the insert / update
def ArrayList rootRetainElements = new ArrayList();
rootRetainElements.add("name");
rootRetainElements.add("version");
rootRetainElements.add( "implementation");
rootRetainElements.add( "details");

def final String cli_params =   "-h or -help -- provides this information\n" + 
								"-inName - user name to access the source management cloud\n" +
								"-inPass - password for the source management cloud\n" +
								"-inSvr - The server address without any attributes e.g. https://1.2.3.4\n" +
								"-policy - numeric identifier for the policy of interest\n"+
								"-iter - iteration number of interest for the policy - optional\n"+
								"-outName - optional, the target management cloud username, only needed for migrations\n" +
								"-outPass - optional, the target management cloud password, only needed for migrations\n" +
								"-outSvr - optional, the target management cloud server address - same formatting as inSvr, only needed for migrations\n"+
								"-override - optional, if migrating to another management, tells the script to replace the existing policy of the samename if found\n"+
								"-view - optional, separate command to allow viewing of the policy - requires one of the following value:\n"+
								"        - display - displays all the details of the policy, if no iteration is provided this will be the latest iteration\n"+
								"        - summary - provides the headline information of the policy including name, change date etc\n" +
								"        - summary-all - summarises all the iterations from the current one back to the 1st\n"
								"-debug - optional, will get script to report more information about what is happening"
								;

try 
{
	
	if (args.size() > 0)
	{

		def int argIdx = 0;
		def int sze = 0;

		if (args != null)
		{
			sze = args.size()
		}
		while (argIdx < sze)
		{

			switch (args[argIdx])
			{

				case "-h":
				case "-help":
		        	println ("Help:\n"+cli_params)
		        	System.exit(0)
		        

		        case '-inName':
		        	inUName = args[argIdx+1]
		        	argIdx += 2

		        	if (outUName == null)
		        	{
		        		outUName = inUName;
		        	}
		        	break;
		        

		        case '-outName':
		        	outUName = args[argIdx+1]
		        	argIdx += 2
		        	break

		        case '-inPass':
		        	inPassword = args[argIdx+1]
		        	argIdx += 2

		        	// if the password hasn't been set default it to match
		        	if (outPassword == null)
		        	{
		        		outPassword = inPassword;
		        	}
		        	break

		        case '-outpass':
		        	outPassword = args[argIdx+1]
		        	argIdx += 2
		        	break

		        case '-inSvr':
		        	inSvr = args[argIdx+1]
		        	argIdx += 2

		        	if (outSvr == null)
		        	{
		        		outSvr = inSvr;
		        	}
		        	break

		        case '-outSvr':
		        	outSvr = args[argIdx+1]
		        	argIdx += 2
		        	break

		        case '-override':
		        	overrideTarget = true
		        	argIdx += 1
		        	break

		        case '-policy':
		        	if (args[argIdx+1].isInteger())
		        	{
		        		apiId = args[argIdx+1].toInteger();
		        	}
		        	else
		        	{
		       		 throw new Exception ("-Iter value is not numeric -- " + args[argIdx+1])
		      		}
		        	argIdx += 2	      		
		        	break

		        case '-iter':
		        	if (args[argIdx+1].isInteger())
		        	{
		        		apiIter = args[argIdx+1].toInteger();
		        	}
		        	else
		        	{
		       		 throw new Exception ("-Iter value is not numeric -- " + args[argIdx+1])
		      		}
		        	argIdx += 2
		        	break

		        case '-view':
		        	view = args[argIdx+1];
		        	argIdx += 2
		        	switch (view)
		        	{
		        		case 'display':
		        		case 'summary':
		        		case 'summary-all':
		        		// legal values so just exist
		        		break;
		        		default:
		        			println ("Illegal value for view :" + view);
		        			println (cli_params);
		        			System.exit (0);
		        	}
		        	break

		        case '-debug':
							displayAll = true;
		        	argIdx += 1;
		        	println ("Debug is set");
		        	break

		        default:
		        	println ("Unknown configuration value:" + args[argIdx] + "\n\n");
		        	println (cli_params);
		        	System.exit(0);

		    }
		}
	}
	else
	{
		println ("No params found - exiting\n\n");
		println (cli_params);
	}

}
catch (Exception err)
{
	println ("Error message:" + err.getMessage() + "\n\n")
	println (cli_params)
	System.exit(0)
}
				


// verify all the parameters
try
{
	assert (inUName.size() > 0) : "No username"
	assert (inPassword.size() > 0) : "No source Password"
	assert (inSvr.size() > 0) : "No server"
	assert (apiId > 0) : "API Id is wrong"
}
catch (AssertionError assertErr)
{
	 println (assertErr.getMessage() + "\n\n")
	 println ("Parameters incomplete:" + cli_params)
	 System.exit(0)
}

// certificate by pass ====================
// http://codingandmore.blogspot.co.uk/2011/07/json-and-ssl-in-groovy-how-to-ignore.html

class OverideHostnameVerifier implements HostnameVerifier
{
	boolean verify(String hostname,
             SSLSession session)
             {return true}
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


 // core API logic from here onward
// provide a function that consistently builds the authentication string to send to the API Platform
public String getAuthString (String uname, String password)
{
		// setup inPassword string
	final String authStringPlain = uname+":"+ password
	final authString = "Basic " + (authStringPlain.getBytes().encodeBase64().toString())

	return authString;
}

// look for the existance of a policy by name in the named instance
public boolean policyExistsInTarget (String policyName, String uname, String password, String svr, TrustManager[] trustAllCerts, SSLContext sc, boolean debug)
{
	// https://example.com/apiplatform/management/v1/apis/preview?fields=vanityName
	if (debug) {println ("Checking in " + svr + " for " + policyName);}

	def boolean matched = false;

	// configure HTTP connectivity inc ignoring certificate validation
	HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
	HttpsURLConnection.setDefaultHostnameVerifier((HostnameVerifier)new OverideHostnameVerifier());

	// get the API list
	String resourcePath = "/apiplatform/management/v1/apis/preview?fields=vanityName";
	def connection = new URL(svr+resourcePath).openConnection();
	connection.setRequestProperty("Content-Type", "application/json");
	connection.setRequestProperty("Authorization", getAuthString(uname, password));
	def jsonAPIDefn = new JsonSlurper().parse(connection.getInputStream());

	if (debug) {println ("checking svr " + svr + " for " + policyName);}

	// loop through the list of API Names

   	def int idx = 0;

   	// search the list of target policies to match for an existing name
	while ((idx < jsonAPIDefn.items.size()) && (!matched))
	{
		if (jsonAPIDefn.items[idx].name == policyName)
		{
			matched = true;
			if (debug) {println ("Found match in svr " + svr + "for " + policyName);}
		}
		idx++;
	}
	return matched;
}

// provides a function to display the policy information so we can do it consistently when presenting a summary view
public void displayPolicySummary (String name, String description, String version, String stateUpdatedAt, String state, String iterationId)
{
	println ("Policy:"+name + "| Version:"  + version + "| Updated at:" + stateUpdatedAt + "| State:"+state + 
				"| Iteration:" + iterationId + "| Description:" + description);
}


 
 // this takes the details to connect to an API platform and push the update object (a representation of the policy) by not differentiating
 // between the magmt cloud queried and the target then we can use this to migrate as easily as revert forward
 // resource path is provided as it will depend upon the operation include the policy identifier or not
 // isInsert tells us which verb will be required
 public void pushPolicy (String resourcePath, String update, boolean isInsert, String uname, String password, String svr, TrustManager[] 
 							trustAllCerts, SSLContext sc, boolean debug)
 {
  	 // configure HTTP connectivity inc ignoring certificate validation
	sc.init(null, trustAllCerts, new java.security.SecureRandom());
	HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
	HttpsURLConnection.setDefaultHostnameVerifier((HostnameVerifier)new OverideHostnameVerifier());

	def String method = 'PUT';
	if (!isInsert)
	{
		method = 'POST'
	}

	if (debug) 
	{
		println ("Target path:" + svr+resourcePath);
		println ("Submitting:\n" + update);
	}

	apiDefnUpdate = new URL(svr+resourcePath).openConnection()
	if (debug) {println ("Calling "+ " operation " + method + " on " + svr+resourcePath);}

	apiDefnUpdate.setRequestProperty("Authorization", getAuthString(uname, password));
	apiDefnUpdate.setRequestProperty("Content-Type", "application/json");
	apiDefnUpdate.setDoOutput(true);
	apiDefnUpdate.setRequestMethod(method);
	apiDefnUpdate.setRequestProperty('User-agent', 'groovy script');

	// retrieve the response
	def out = new OutputStreamWriter(apiDefnUpdate.outputStream);
	out.write(update);
	out.close();
	//def response = new JsonSlurper().parse(apiDefnUpdate.inputStream)
	println ("Update response:"+apiDefnUpdate.responseCode + " : " + apiDefnUpdate.responseMessage);  	
 }

 // this function will pull down the policy object from the management cloud providing a slurped JSON object
 // requires the policy numeric Id, the iteration - if the iteration is 0 then we get the latest iteration of the policy
 // plus credentials to connect to the server
 public Object getPolicy (int apiId, int apiIter, String uname, String password, String svr, TrustManager[] trustAllCerts, SSLContext sc, boolean debug)
 {
 		// configure HTTP connectivity inc ignoring certificate validation
	sc.init(null, trustAllCerts, new java.security.SecureRandom());
	HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
	HttpsURLConnection.setDefaultHostnameVerifier((HostnameVerifier)new OverideHostnameVerifier());


	// get the API policy
	String resourcePath = "/apiplatform/management/v1/apis/"+apiId;
	if (apiIter > 0 )
	{
		// if we're after a specific iteration then add it to the path, otherwise we default to the latest iteration
		resourcePath = resourcePath + "/iterations/" + apiIter;
	}

	if (debug) {println ("retrieving:" + svr+resourcePath);}
	def apiDefn = new URL(svr+resourcePath).openConnection()
	apiDefn.setRequestProperty('Authorization', getAuthString(uname, password))

	def jsonAPIDefn = new JsonSlurper().parse(apiDefn.getInputStream())
	if (debug) {println (new JsonBuilder(jsonAPIDefn).toPrettyString());}
	return jsonAPIDefn;
 }

// main

try 
{
	// create a context to work with
	SSLContext sc = SSLContext.getInstance('SSL');

	def jsonAPIDefn = getPolicy(apiId, apiIter, inUName, inPassword, inSvr, trustAllCerts, sc, displayAll)
	if (displayAll) { println (new JsonBuilder(jsonAPIDefn).toPrettyString()) }

	//if the action is just to view then exit NOW
	 if (view != null)
	 {
	 	 if (view == "display") // display the entire policy
	 	 {
	 	 	println (new JsonBuilder(jsonAPIDefn).toPrettyString());
	 	 }
	 	 else if (view == 'summary') // display the policy summary
	 	 {
	 	 	displayPolicySummary (jsonAPIDefn.name,	jsonAPIDefn.details.description, jsonAPIDefn.version,
	 	 							jsonAPIDefn.stateUpdatedAt, jsonAPIDefn.state, jsonAPIDefn.iterationId);
	 	 }
	 	 else if (view=='summary-all')
	 	 {
	 	 	// loop through all iterations printing the summary
	 	 	def int iterLoop = jsonAPIDefn.iterationId.toInteger()
	 	 	iterLoop -= 1;

	 	 	 displayPolicySummary (jsonAPIDefn.name, jsonAPIDefn.details.description, jsonAPIDefn.version, 
	 	 	 						jsonAPIDefn.stateUpdatedAt,	jsonAPIDefn.state, jsonAPIDefn.iterationId);

	 	 	 // loop through all the iterations from the current one going back and get the summary view
	 	 	while (iterLoop > 0)
	 	 	{
				jsonAPIDefn = getPolicy(apiId, iterLoop, inUName, inPassword, inSvr, trustAllCerts, sc, displayAll)
	 	 	 	displayPolicySummary (jsonAPIDefn.name, jsonAPIDefn.details.description, jsonAPIDefn.version, 
	 	 	 							jsonAPIDefn.stateUpdatedAt, jsonAPIDefn.state, jsonAPIDefn.iterationId);
				iterLoop -= 1;
	 	 	}

	 	 }
	 }
	 else
	 {

		// modify the policy description
		jsonAPIDefn.details.description =  "Been subject to a reversion script " + jsonAPIDefn.details.description;

		def removalList = new ArrayList();

		// look through the elements and identify what can be removed
		jsonAPIDefn.keySet().each
		{
			if (!(rootRetainElements.contains(it)))
			{
				removalList.add(it);
			}
		}

		// loop through the removal list and take them out of the source JSON
		removalList.each
		{
			jsonAPIDefn.remove (it);
		}


		def boolean isInsert = true;
		// set the path for the update
		if (inSvr == outSvr)
		{
			// we're working with the same API - so it exists
			if (displayAll) {println ("reverting forward")}
			resourcePath = "/apiplatform/management/v1/apis/"+apiId;
			isInsert=true;
			jsonAPIDefn.details.description += ' apply reversion to iteration '  + apiIter;	
		}
		else
		{
			// assume we're migrating from one server to another
			if (displayAll) {println ("migrating")}

			resourcePath = "/apiplatform/management/v1/apis/"+apiId;
			isInsert=false;

			//test to see if already exists in target
			if (policyExistsInTarget (jsonAPIDefn.name, outUName, outPassword, outSvr,trustAllCerts, sc, displayAll))
			{
				println ("confirmed match")
			}

			// have we got a entry already in the target environment and are we allowed to override it?
			if (overrideTarget && matched)
			{
				isInsert=false;
			}
			else
			{
				// report conflict and exit process
				println ("Found " + jsonAPIDefn.name + " exists in " + outSvr + " aborting");
				System.exit(0)
			}
			jsonAPIDefn.details.description += ' was iteration '  + apiIter + " on API Platform " + inSvr;
		}
		pushPolicy (resourcePath, (new JsonBuilder(jsonAPIDefn).toPrettyString()), isInsert, outUName, outPassword, outSvr, trustAllCerts, sc, displayAll);

	}
} 
catch (Exception err) 
{
	err.printStackTrace()
	println ("Error:"+err.getMessage())
}

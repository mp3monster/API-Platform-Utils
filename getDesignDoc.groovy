import groovy.json.*
import java.net.URLConnection
import javax.net.ssl.*

DisplayAll = false // allows us to pretty print all the API calls if necessary

// if defaults are set then calling with the default values will attempted
def String uname = null
def String password = null
//def String svr = "https://130.162.67.188"
def String svr = null

DisplayAllCLI = "-d"

final MATCHAPP = "APP"
final MATCHNAME = "NAME"
def String matchType = MATCHNAME
matchParam = "-m"

MatchNameParam = "-n"
def String matchName = null
DefaultFileName = "APIDoc"
def String SingleFileName = DefaultFileName
final String fnParam = "-f"
// default to true so theat the finemae in the API NAME
// if the -f option is used then this goes to false and SingleFileName is set
def boolean MultiFile = true

// switches to tailor info logged
IncludeChangeInfo = true
ChangeInfoCLIParam = "CHANGEINFO"
IncludeVersionInfo = true
VersionInfoCLIParam = "VERSIONINFO"
IncludePolicyInfo = true
PolicyInfoCLIParam = "POLICYINFO"
IncludeAppInfo = true
IncludeDraftPoliciesInfo = true

StopDocElement = "-s"

Authorization = "Authorization"


// string for printing the output
NL = "\n"
H1 = " #"
H2 = " ##"
H3 = " ###"
LST = " * "
Bold = "**"
Separator = "  "
Rule = "---" + NL
APIsHeader = "APIs"
APPsHeader = "APPs"
VersionHeader = "Version"
ChangeHeader = " Creation & Amendment"
PolicyHeader =  "Policies"
RequestsHeader = "Requests"
ResponsesHeader = "Responses"
CreatedOn = "Created On:"
UpdatedOn = "Updated On:"
CreatedONLabel =  CreatedOn
UpdatedONLabel = UpdatedOn

VersionNoLabel = "Version No."
StateLabel = "State:"
IteratioNLabel = "Iteration No:"

PolicyTypeLabel = "Policy:"


noDescription = " -- No Description Available --"
FilePostfix = ".md"

AppRef = "references.applications"

if (args.size() > 0)
{
	try
	{
		svr = args [0]
		uname = args[1]
		password = args [2]

		println ("svr="+svr + "\nusername ="+uname+"\nPassword =" + password)

		def idx = 3
		while (idx < args.size())
		switch (args[idx])
		{
			case fnParam :
			if (args.length() > idx+1)
			{
				idx = idx+1
				SingleFileName = args[idx]
				SingleFileName.trim()

				if (SingleFileName.length() == 0 )
				{
					println ("Malformed filename parameter")
					SingleFileName = DefaultFileName + FilePostfix
				}
				else
				{
					// its a legitimate filename - so switch on single file
					MultiFile = false
					idx++
				}
			}
			break

			case matchParam :
			String matchCommand = null
			idx++
			if (args.size() >= idx)
			{
				matchCommand = args[idx]
				matchCommand = matchCommand.toUpperCase()
			}
			if (matchCommand == MATCHAPP)
			{
				matchType = MATCHAPP
			}
			else if (matchCommand == MATCHNAME)
			{
				matchType = MATCHNAME
			}
			else
			{
				println ("didn't understand match type param:" + matchCommand + " disreguarding")
			}
			break

			case MatchNameParam :
			idx++
			if (args.size() >= idx)
			{
				matchName = args[idx]
			}
			else
			{
				println ("No name provided as a filter")
			}

			case DisplayAllCLI:
			DisplayAll = true
			println ("Display All Enabled")
			idx++
			break

			case StopDocElement:
			def String elementsParam = null
			idx++
			if (args.size() >= idx)
			{
				elements = args[idx]
				elements = elements.toUpperCase()
				def List elements = elements.tokenize(',')
				for (listIdx =0; listIdx < elements.size(); listIdx++)
				{
					switch (elements[listIdx])
					{
						case VersionInfoCLIParam:
						IncludeVersionInfo = false
						println ("Version Info now OFF")
						break

						case PolicyInfoCLIParam:
						IncludePolicyInfo = false
						println ("Policy Info now OFF")
						break

						case ChangeInfoCLIParam:
						IncludeChangeInfo = false
						println ("Change Info now OFF")
						break

						default:
						println ("Don't recognize " + elements[listIdx] + " ignoreing")
					}
				}
			}
			break

			default:
			println ("Unknown parameter - "+args[idx])
			idx++
		}
	}
	catch (Exception err)
	{
		println ("Expect server username password")
		err.printStackTrace()
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
catch (Exception err)
{
	println (err.getMessage()  + "\n")
	if (DisplayAll) {	err.printStackTrace()}
	println ("\nExpect server username password\n\n")
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
				java.security.cert.X509Certificate[] certs, String authType) {	}
			}

			TrustManager[] trustAllCerts = new TrustManager[1]

			trustAllCerts[0] = new TrustManager()

			// ================================================================

			void matchAPIName (Object apiData, ArrayList apis, String matchName, String apiDataURL)
			{
				def String apiName = apiData.vanityName

				if (apiName == null)
				{
					apiName = apiData.name
				}

				if ((apiName != null) &&  (matchName != null))
				{
					if (apiName.contains(matchName))
					{
						apis.add (apiDataURL);
					}
				}
			}

			void matchAppName (Object apiData, ArrayList apis, String matchName,  String apiDataURL)
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
								if (DisplayAll) {println ("Found APP ref for " + apiData.name)}
								def app = new URL(apiData.links[apiRefCtr].href).openConnection()
								app.setRequestProperty(Authorization, authString)
								def appData = new JsonSlurper().parse(app.getInputStream())
								if ((appData.items != null) && (appData.items[0] != null) && (appData.items[0].name != null))
								{
									if (appData.items[0].name.contains(matchName))
									{
										apis.add (apiDataURL);
										if (DisplayAll) {
											println ("MATCHED App name:" + appData.items[0].name + " with " + matchName)
										}

									}
									else
									{
										if (DisplayAll)
										{
											println ("NOT matched App name: " + appData.items[0].name)
										}
									}
								}
							}
					}
				}
				else
				{
					println ("Found no links ref for " + apiData.name )
				}
			}
			catch (FileNotFoundException err)
			{
				println ("No URL for " + err.getMessage())
			}
		}


StringBuffer processPolicies (Object apiData, StringBuffer sb, HashMap policyMetadata)
{
	Boolean addHeader = true
	HashMap policyTexts = new HashMap();

	for (policyCtr = 0; policyCtr < apiData.implementation.policies.size(); policyCtr++)
	{
		StringBuffer line = new StringBuffer()
		if (((IncludeDraftPoliciesInfo) && (apiData.implementation.policies[policyCtr].draft == true)) ||
		(apiData.implementation.policies[policyCtr].draft != true))
		{

			if (apiData.implementation.policies[policyCtr].type != null)
			{
				def policyMetadataEntry = policyMetadata.get(apiData.implementation.policies[policyCtr].type)
				if (DisplayAll) { println ("policy metadata retrieved :" +new JsonBuilder(policyMetadataEntry).toPrettyString()+NL+NL) }

				line.append (Bold + PolicyTypeLabel + Bold + policyMetadataEntry.name)
				def String policyDescription = null

				// get the description if there isnt a specific one for this policy instance, retrieve the policy standard definition
				policyDescription = apiData.implementation.policies[policyCtr].comment
				if (policyMetadataEntry != null)
				{
					if ((policyDescription == null) || (policyDescription.length() == 0))
					{
						policyDescription = policyMetadataEntry.description
						if (DisplayAll) {println ("getting policy description from the cached metadata - "+policyMetadataEntry.description)}
					}
				}

				if (policyDescription != null)
				{
					line.append ( " : " + policyDescription + NL)
				}
				line.append (NL)
				if (DisplayAll) { println ("policy info:" +new JsonBuilder(apiData.implementation.policies[policyCtr]).toPrettyString()+NL+NL) }
			}
		}
		policyTexts.put (apiData.implementation.policies[policyCtr].id, line)
	}


	sb.append(H2 + " " + PolicyHeader + NL)
	sb.append (H3+RequestsHeader + NL)
	for (requestCtr = 0; requestCtr < apiData.implementation.executions.request.size(); requestCtr++)
	{
  	sb.append (policyTexts.get(apiData.implementation.executions.request[requestCtr]))
	}

	sb.append (H3+ResponsesHeader + NL)
	for (responseCtr = 0; responseCtr < apiData.implementation.executions.response.size(); responseCtr++)
	{
  	sb.append (policyTexts.get(apiData.implementation.executions.response[responseCtr]))
	}

	return sb
}


// put together the description of the policies
StringBuffer processAppDetails (StringBuffer sb, Object appObj, HashMap appDescCache, String svr, String authString)
{
	sb.append (H2 + " " + APPsHeader + NL)
	sb.append  (appObj.items[0].name)
	def String description = null

	// get the app Description
	if (appDescCache.containsKey(appObj.items[0].id))
	{
		// have the description cached use that
		description = appDescCache.get(appObj.items[0].id)
		if (DisplayAll) { println ("used description cache")}
	}
	else
	{
		// need to go look up the descriptions
		def appdescURL = new URL(svr + "/apiplatform/management/v1/applications/"+ appObj.items[0].id).openConnection()
		appdescURL.setRequestProperty(Authorization, authString)
		def appDescObj = new JsonSlurper().parse(appdescURL.getInputStream())
		description = appDescObj.description
		appDescCache.put ( appObj.items[0].id, description)
		if (DisplayAll)
		{
			println ("looked up description")
		  println (new JsonBuilder(appDescObj).toPrettyString())
		}
	}

	// have I managed to obtain a meaningful description text
	if ((description != null) && (description.length() > 0))
	{
		sb.append( ": "+description + NL)
	}

	return sb
}

		//===============


		// main

		def HashMap policyMetadata = new HashMap();
		def ArrayList apis = new ArrayList() // k=api.id, v=https://docs.oracle.com/en/cloud/paas/api-platform-cloud/apfrm/op-apis-%7BapiId%7D-get.html

		// setup password string
		final String authStringPlain = uname+":"+password
		final authString = "Basic " + (authStringPlain.getBytes().encodeBase64().toString())
		// configure HTTP connectivity inc ignoring certificate validation
		SSLContext sc = SSLContext.getInstance("SSL");
		sc.init(null, trustAllCerts, new java.security.SecureRandom());
		HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
		HttpsURLConnection.setDefaultHostnameVerifier((HostnameVerifier)new OverideHostnameVerifier());



		try
		{
			// get policy metadata
			def callPoliciesMetadata = new URL(svr+"/apiplatform/management/v1/policies/metadata").openConnection()
			callPoliciesMetadata.setRequestProperty(Authorization, authString)
			def jsonPolicyMetaList = new JsonSlurper().parse(callPoliciesMetadata.getInputStream())
			if (DisplayAll) {
				println ("****** policy meta data *****")
				println (new JsonBuilder(jsonPolicyMetaList).toPrettyString())
				println ("*****************************")
			}


			for (policyMetaIdx=0; policyMetaIdx < jsonPolicyMetaList.count; policyMetaIdx++)
			{
				policyMetadata.put (jsonPolicyMetaList.items[policyMetaIdx].type, jsonPolicyMetaList.items[policyMetaIdx])
			}

			// get the API list and then iterate through pulling the API information - record the API info into a map
			def listAPIs = new URL(svr+"/apiplatform/management/v1/apis").openConnection()
			listAPIs.setRequestProperty(Authorization, authString)
			def listAPIData = new JsonSlurper().parse(listAPIs.getInputStream())


			for (idx = 0; idx <  listAPIData.count; idx++)
			{
				def apiDataURL = svr + "/apiplatform/management/v1/apis/" + listAPIData.items[idx].id
				//println ("requesting : " + apiDataURL)
				def api = new URL(apiDataURL).openConnection()
				api.setRequestProperty(Authorization, authString)
				def apiData = new JsonSlurper().parse(api.getInputStream())

				switch (matchType)
				{
					case MATCHNAME:
					matchAPIName (apiData, apis, matchName, apiDataURL)
					break;
					case MATCHAPP:
					matchAppName (apiData, apis, matchName, apiDataURL)
					break
				}
			}
		}
		catch (Exception excep)
		{
			excep.printStackTrace()
		}

		if (DisplayAll)
		{
			println ("located APIs to document/n======================================/n======================================")
			println ("generating docs for " + apis.size() + " APIs")
		}
		def String fileName = null
		def HashMap appDescCache = new HashMap()
		// cache the app descriptions so we dont keep having to look it up
		def File file = null
		if (!MultiFile)
		{
			fileName = SingleFileName+FilePostfix
			if	(DisplayAll) {println ("Single File Output to " + fileName)}
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
					fileName = apiData.name+FilePostfix
					file = new File(fileName)

					if (file.exists())
					{
						file.delete()
					  //println ("deleted old version of " + fileName)
					}
					file.createNewFile()
				}

				sb.append (H1)
				sb.append(apiData.name + NL)
				if ((apiData.description != null) && (apiData.description.length() > 0))
				{
					sb.append (apiData.description + NL)
				}
				else
				{
					sb.append (noDescription + NL)
				}

				if (IncludeVersionInfo)
				{
					if	(DisplayAll) {println ("Including version info for " + apiData.name)}
					sb.append (H2+ VersionHeader + NL)
					sb.append (Bold + VersionNoLabel + Bold + apiData.version)
					sb.append (Separator + Bold + StateLabel + Bold + apiData.state + NL)
					sb.append (Bold + IteratioNLabel + Bold + apiData.iterationId + NL)
				}

				if (IncludeChangeInfo)
				{
					if	(DisplayAll) {println ("Including change info for " + apiData.name)}
					sb.append (H3 + ChangeHeader + NL)
					sb.append (Bold + CreatedONLabel + Bold + apiData.createdAt)
					sb.append (Separator + Bold + UpdatedONLabel + Bold + apiData.updatedAt + NL)
				}

				// locate the app info and write
				if (IncludeAppInfo)
				{
					if	(DisplayAll) {println ("Including app info for " + apiData.name)}
					if (apiData.links != null)
					{
						for (linkCtr = 0; linkCtr < apiData.links.size(); linkCtr++)
						{
							if (( apiData.links[linkCtr].rel != null) && (apiData.links[linkCtr].rel == AppRef))
							{
								def appURL = new URL(apiData.links[linkCtr].href).openConnection()
								appURL.setRequestProperty(Authorization, authString)
								def appObj = new JsonSlurper().parse(appURL.getInputStream())
								if ((appObj.items != null) && (appObj.items[0] != null) &&
								(appObj.items[0].name != null))
								{
									sb = processAppDetails (sb, appObj, appDescCache, svr, authString)
								}
							}
						}
					}
				} // end of app info

				if (IncludePolicyInfo)
				{
					if	(DisplayAll) {println ("Including policy info for " + apiData.name)}
						// provide the policy info
					if (apiData.implementation.policies != null)
					{
						sb = processPolicies (apiData, sb, policyMetadata)
					}
				}

			}
			catch (Exception err)
			{
					err.printStackTrace()
			}
			if (!MultiFile) {sb.append(NL + Rule)}
			//println ("Writing to file:"+fileName)
			if (DisplayAll) {println (sb.toString() + "\n ++++++++++++++++++++++++++++++++++++++++++++++++++++")}
			file.append(sb.toString())
	}

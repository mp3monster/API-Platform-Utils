//license : http://creativecommons.org/licenses/by/4.0/
//Creative Commons License
//This work is licensed under a Creative Commons Attribution 4.0 International License
// CC BY

import groovy.json.*
import java.net.URLConnection
import javax.net.ssl.*

DisplayAll = false // allows us to pretty print all the API calls if necessary

// if defaults are set then calling with the default values will attempted
def String uname = null
def String password = null
//def String svr = "https://130.162.67.188"
def String svr = null

DisplayHelp = "-h"

DisplayAllCLI = "-d"

MATCHAPP = "APP"
MATCHAPPNO = 0
MATCHAPI = "API"
MATCHAPINO = 1
MatchType = MATCHAPINO
MatchTypeParam = "-m"

MatchNameParam = "-n"
TargetName = null
DefaultFileName = "APIDoc"
def String SingleFileName = DefaultFileName
FileNameParam = "-f"
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
CheckForExclusion = false
ExclusionInfoCLIParam = "EXCLUDE"
COMMENTEXCLUDETEXT="EXCLUDE"

StopDocParam = "-s"

// API call header property
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

NOREQUESTTODISPLAY = "-- No Requests to Display --"
NORESPONSETODISPLAY = "-- No Responses to Display --"

noDescription = " -- No Description Available --"
FilePostfix = ".md"

AppRef = "references.applications"



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


			ArrayList matchAPIName (Object apiData, ArrayList apis, String name, String apiDataURL)
			{
				def String apiName = apiData.vanityName

				if (apiName == null)
				{
					apiName = apiData.name
				}

				if ((apiName != null) && (name != null))
				{
					if (apiName.contains(name))
					{
						apis.add (apiDataURL)
						if (DisplayAll)
						{
							println ("Matched API " + apiName)
						}
					}
				}
				else
				{
					apis.add (apiDataURL);
					if (DisplayAll)
					{
						println ("Matched API " + apiName)
					}
				}
				return apis
			}

			// look to match against App names
			ArrayList matchAppName (Object apiData, ArrayList apis, String name,  String apiDataURL)
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
								// if there is no match name we add everything to the list
								if ((appData.items != null) && (appData.items[0] != null) && (appData.items[0].name != null))
								{
									if ((name == null) || (appData.items[0].name.contains(name)))
									{
										apis.add (apiDataURL);
										if (DisplayAll)
										{
											println ("MATCHED App name:" + appData.items[0].name + " with " + name)
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
				if (DisplayAll)
				{
					println ("No URL for " + err.getMessage())
				}
			}

			return apis
		}

// evaluate how to process the policies and then build output display
StringBuffer processPolicies (Object apiData, StringBuffer sb, HashMap policyMetadata)
{
	Boolean addHeader = true
	HashMap policyTexts = new HashMap();

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
				if (DisplayAll) { println (NL+"policy to evaluate :" +new JsonBuilder( apiData.implementation.policies[policyCtr]).toPrettyString()) }

				def policyMetadataEntry = policyMetadata.get(apiData.implementation.policies[policyCtr].type)

				line.append (Bold + PolicyTypeLabel + Bold + policyMetadataEntry.name)
				def String policyDescription = null

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
						if (DisplayAll) {println ("getting policy description from the cached metadata - "+policyMetadataEntry.description)}
					}
				}

				// devaluate and action exclusion if set
				if ((policyDescription != null) &&
					CheckForExclusion &&
					(policyDescription.endsWith(COMMENTEXCLUDETEXT)))
				{
					if (DisplayAll){println ("Applying exclusion to " + policyMetadataEntry.name)}
						// instruction to exclude this policy has been allocated
						policyDescription = null
						line = null
				}

				if (policyDescription != null)
				{
					line.append ( " : " + policyDescription + NL)
				}
				if (line != null)
				{
					line.append (NL)
				}
				if (DisplayAll) { println ("policy info:" +new JsonBuilder(apiData.implementation.policies[policyCtr]).toPrettyString()+NL+NL) }
			}
		}
		policyTexts.put (apiData.implementation.policies[policyCtr].id, line)
	}


	sb.append(H2 + " " + PolicyHeader + NL)
	sb.append (H3+RequestsHeader + NL)
	int lineCount = 0;
	for (requestCtr = 0; requestCtr < apiData.implementation.executions.request.size(); requestCtr++)
	{
		requestLine = policyTexts.get(apiData.implementation.executions.request[requestCtr])
		if (requestLine != null)
		{
			sb.append (requestLine)
			lineCount++
		}
	}

	if (lineCount == 0)
	{
		sb.append (NOREQUESTTODISPLAY)
	}

	sb.append (H3+ResponsesHeader + NL)
	lineCount = 0
	for (responseCtr = 0; responseCtr < apiData.implementation.executions.response.size(); responseCtr++)
	{
		responseLine = policyTexts.get(apiData.implementation.executions.response[responseCtr])
		if (responseLine != null)
		{
	  	sb.append (responseLine)
			lineCount++
		}
	}
	if (lineCount == 0)
	{
		sb.append (NORESPONSETODISPLAY)
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

void DisplayHelp()
{
	println ("================================================\nHelp:\n")
	println ("Mandatory to provide server-url username password e.g. https://1.2.3.4/ me myPassword\n")
	println ("Without these parameters the app will stop\n")
	println ("optional parameters:")
	println (DisplayAllCLI+" == displays all the activity information")
	println (DisplayHelp+" == this information")
	println (MatchNameParam + " <string> == used to apply a filter on the app or API name,\nif nothing set then all APIs are included")
	println ("If the string contains spaces then this can be addressed by wrapping \nwith double quotes e.g. \"my multipart name\"")
	println (MatchTypeParam + " <"+MATCHAPI+"|"+MATCHAPP+"> == apply the name filter to API names or App names, default is API")
	println (FileNameParam+" <filename> == target the output to a single file, \nif not set each API is written to its own file")
	println (StopDocParam+" <"+ChangeInfoCLIParam+"|"+VersionInfoCLIParam+"|"+PolicyInfoCLIParam+"|"+ExclusionInfoCLIParam+"> == stop the sections being included, \nmultiple elements can be included by comma separating without space characters")
	println ("the "+ExclusionInfoCLIParam+ " is a special case as it looks in the policy comment to see if ends with " + COMMENTEXCLUDETEXT + " \nif present, that policy is excluded from the output")
	println ("")
	println ("All commands are case sensitive")
	println ("Tool doc at: http://blog.mp3monster.org/2018/05/18/documenting-apis-on-the-oracle-api-platform")
	println ("================================================\n")
	System.exit(0)
}

		//===============

 	// handle CLI
	println ("at CLI with " + args.size() + " args\n" + args.toString())
	if (args.size() > 0)
	{
		try
		{
			if (args.size() < 3 || (args[0] == DisplayHelp))
			{
				DisplayHelp()
			}
			svr = args [0]
			uname = args[1]
			password = args [2]

			id (DisplayAll) {println ("svr="+svr + "\nusername ="+uname+"\nPassword =" + password)}

			def idx = 3
			while (idx < args.size())
			switch (args[idx])
			{
				case FileNameParam :
				if (args.size() > idx+1)
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

				case MatchTypeParam :
					String matchCommand = null
					idx++
					if (args.size() >= idx)
					{
						matchCommand = args[idx]
						matchCommand = matchCommand.toUpperCase()
						idx++
					}
					if (matchCommand == MATCHAPP)
					{
						MatchType = MATCHAPPNO
					}
					else if (matchCommand == MATCHAPI)
					{
						MatchType = MATCHAPINO
					}
					else
					{
						if (DisplayAll)	{println ("didn't understand match type param:" + matchCommand + " disreguarding")}
						MatchType = MATCHAPINO
					}
					break

				case MatchNameParam :
					idx++
					if (args.size() >= idx)
					{
						TargetName = args[idx]
						idx++
					}
					else
					{
						if (DisplayAll){println ("No name provided as a filter")}
					}
					break

				case DisplayAllCLI:
					DisplayAll = true
					println ("Display All Enabled")
					idx++
					break

				case DisplayHelp:
					DisplayHelp()
					idx++
					System.exit(0)
					break

				case StopDocParam:
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
								if (DisplayAll) {println ("Version Info now OFF")}
								break

								case PolicyInfoCLIParam:
								IncludePolicyInfo = false
								if (DisplayAll) {println ("Policy Info now OFF")}
								break

								case ChangeInfoCLIParam:
								IncludeChangeInfo = false
								if (DisplayAll) {println ("Change Info now OFF")}
								break

								case ExclusionInfoCLIParam:
								CheckForExclusion = true
								if (DisplayAll) {println ("checking for exclusion tag in descriptions")}
								break

								default:
								if (DisplayAll) {println ("Don't recognize " + elements[listIdx] + " ignoring")}
							}
						}
						idx++
					}
				break

				default:
				println ("Unknown parameter - "+args[idx])
				idx++
			}
		}
		catch (Exception err)
		{
			if (DisplayAll)
			{
				println (err.getMessage())
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
		DisplayHelp()
		System.exit(0)
	}

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
				if (DisplayAll){println ("requesting : " + apiDataURL)}
				def api = new URL(apiDataURL).openConnection()
				api.setRequestProperty(Authorization, authString)
				def apiData = new JsonSlurper().parse(api.getInputStream())

				switch (MatchType)
				{
					case MATCHAPINO:
						apis = matchAPIName (apiData, apis, TargetName, apiDataURL)
						break

					case MATCHAPPNO:
						apis = matchAppName (apiData, apis, TargetName, apiDataURL)
						break

					default:
					 if (DisplayAll) {println ("Unknown match type! :" + MatchType)}
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
			println ("======================================")
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

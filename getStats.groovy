//license : http://creativecommons.org/licenses/by/4.0/
//Creative Commons License
//This work is licensed under a Creative Commons Attribution 4.0 International License
// CC BY

import groovy.json.*
import java.net.URLConnection
import javax.net.ssl.*
import groovy.transform.Field

DisplayAll = false // allows us to pretty print all the API calls if necessary
DisplayAllCLI = "-d"

// if defaults are set then calling with the default values will attempted
def String uname = null
def String password = null
def String svr = null

@Field CompleteGatewayList = []
@Field CompleteAPIList = []
@Field int totalAPICalls = 0
@Field CompleteAppsList = []

DisplayHelp = "-h"

ALLGateways="ALL"

DefaultFileName ="report.csv"
FileNameCLIParam = "-f"
ReportFileName = DefaultFileName
// defines the filename to be used

// API call header property
Authorization = "Authorization"


DataTypeCLIParam="-t"
AppDataTypeShortLabel="apps"
AppDataTypeLabel="applications"
ApiDataTypeLabel="apis"
AppsList = 0
APIsList = 1
ListType = AppsList

// allow the category to be configurable against apiIds or appIds
DataGrouping = "apiIds"

// allow duration choicers of last7days, last30days, last365days
ReportDuration30DayLabel="last30days"
ReportDuration7DayLabel="last7days"
ReportDuration1DayLabel="last24hours"
ReportDurationYearLabel="last365days"
ReportDurationLabel = ReportDuration30DayLabel
Days365Duration=0
Days30Duration=1
Days7Duration=2
Days1Duration=3
ReportDurationId=Days30Duration
DurationCLIParam = "-p" // for period

DAY="DAY"
MONTH="MONTH"
HOUR="HOUR"

LogicalGateway = "PROD"
LoglicalGatewayCLIParam = "-g"

SEP = "," // the delimiter/separator to use

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


void outputTotals (String timeQuantity)
{
	println ("======================")
	println ("==      Stats       ==")
	println ("Total gateways = " + CompleteGatewayList.size())
	println ("Total APIs = " + CompleteAPIList.size())
	println ("Total API calls = " + totalAPICalls + " over " + timeQuantity)
	println ("Total Apps = " + CompleteAppsList.size())
	println ("======================")

}

void DisplayHelp()
{
	println ("================================================\nHelp:\n")
	println ("Mandatory to provide server-url username password e.g. https://1.2.3.4/ me myPassword\n")
	println ("Without these parameters the app will stop\n")
	println ("optional parameters:")
	println (DisplayAllCLI+" == displays all the activity information")
	println (DisplayHelp+" == this information")
	println ("")
	println (FileNameCLIParam+" == output filename, if not defined the default report.csv will be used")
	println (LoglicalGatewayCLIParam + " == the name of the gateway or environment e.g. PTE, CTEF, PPE, PROD")
	println (DataTypeCLIParam + " == whether the output should be based upon <APIs|APPs>" )
	println (DurationCLIParam + " == period that the data set will cover using the following numeric options:")
	println ("            0 : Last 365 Days  - returns a value per month")
	println ("            1 : Last 30  Days  - returns a value per day")
	println ("            2 : Last 7   Days - returns a value per day")
	println ("            3 : Last 1   Day  - returns a value per hour")
	println (" This will default to the Last 30 days")

	println ("================================================\n")
	System.exit(0)
}

	//===============
 	// handle CLI
	if (DisplayAll) {println ("at CLI with " + args.size() + " args\n" + args.toString())}
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

			if (DisplayAll) {println ("svr="+svr + "\nusername ="+uname+"\nPassword =" + password)}

			if (args.size() > 3)
			{
				int argIdx = 3
				while (argIdx < args.size())
				{
					switch (args[argIdx])
					{
						case DurationCLIParam:
						argIdx++
						if ((args.size() > argIdx) && (args[argIdx] != null))
						{
							try
							{
								int option = args[argIdx].toInteger()
								if ((option >= 0) && (option < 4))
								{
									ReportDurationId=option
								}
								else
								{
									println ("Option " + option + " Not available, continue with default")
								}
							}
							catch (Exception err)
							{
								println ("Error converting value provided - will use default")
							}
							argIdx++
						}
						break

						case DataTypeCLIParam:
							argIdx++
							if ((args.size() > argIdx) && (args[argIdx] != null))
							{
								args[argIdx] = args[argIdx].toLowerCase()
								if ((args[argIdx] == AppDataTypeShortLabel) ||
								(args[argIdx] ==AppDataTypeLabel))
								{
									ListType = AppsList
									argIdx++
								}
								else if (args[argIdx] == ApiDataTypeLabel)
								{
									ListType = APIsList
									argIdx++
								}
								else
								{
									println ("Ignoring value " + args[argIdx])
									argIdx++
								}
							}
							else
							{
								println ("Couldn't set gateway")
							}
						break

						case LoglicalGatewayCLIParam:
							argIdx++
							if ((args.size() > argIdx) && (args[argIdx] != null))
							{
								LogicalGateway = args[argIdx]
								println ("Will get data for " + LogicalGateway + " gateway(s)")
								argIdx++
							}
							else
							{
								println ("Couldn't set gateway")
							}
						break

						case FileNameCLIParam:
							argIdx++
							if ((args.size() > argIdx) && (args[argIdx] != null))
							{
								ReportFileName = args[argIdx]
								argIdx++
							}
							else
							{
								println ("Couldn't set filename")
							}
						break

						case DisplayHelp:
							DisplayHelp()
							argIdx++
						break

						case DisplayAllCLI:
							DisplayAll = true
							argIdx++
						break

						default:
							println ("Unknown parameter:" + args[argIdx] + " ignorting")
							argIdx++
					}
				}
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
		println ("Error 2")
		if (DisplayAll) {	err.printStackTrace()}
		DisplayHelp()
		System.exit(0)
	}

///=================================================

// get the Ids of the apps or APIs as the same basic data structure is returned
// we can switch the query and then execute the same logic for the rest
HashMap getIds (int listType, String authString, String svr, ArrayList trackerList)
{
	String query = null
	HashMap result = new HashMap()

	switch (listType)
	{
		case AppsList:
		query = svr+"/apiplatform/management/v1/applications"
		break

		case APIsList:
		query = svr+"/apiplatform/management/v1/apis"
		break

		default:
		println ("Unexpected option")
	}

	def listURL = new URL(query).openConnection()
	listURL.setRequestProperty(Authorization, authString)
	JSONData = new JsonSlurper().parse(listURL.getInputStream())

	int count = JSONData.count
	for (int idx = 0; idx < count; idx++)
	{
		result.put (JSONData.items[idx].id.toInteger(), JSONData.items[idx].name)
		if (DisplayAll){println ("Adding:(" + JSONData.items[idx].id + ")" + JSONData.items[idx].name)}

		if (!trackerList.contains (JSONData.items[idx].name))
		{
			trackerList.add(JSONData.items[idx].name)
		}
	}

	if (DisplayAll){println ("Data retrieved for type " + listType + ":\n" +new JsonBuilder(JSONData).toPrettyString())}

return result
}


String  getGatewayIds (String svr, String authString, String gatewayType)
{
	String gwayTypeLower = gatewayType.toLowerCase()
	String query = svr + "/apiplatform/management/v1/gateways/"
	StringBuffer gatewayIds = new StringBuffer();

	if (DisplayAll)	{println ("Looking for "+gatewayType)}

	def queryURL = new URL(query).openConnection()
	queryURL.setRequestProperty(Authorization, authString)
	def JSONData = new JsonSlurper().parse(queryURL.getInputStream())
	// locate the gateway Ids based on environment

	if (DisplayAll){println ("Gateways:\n" +new JsonBuilder(JSONData).toPrettyString())}

	for (int idx = 0; idx < JSONData.count; idx++)
	{
		String name = JSONData.items[idx].name.toLowerCase()
		if (name.startsWith(gwayTypeLower) || (gatewayType==ALLGateways))
		{
			if (gatewayIds.size() > 0)
			{
				gatewayIds.append(SEP)
			}
			gatewayIds.append(JSONData.items[idx].id)

			println ("Gateway " + name + " (" +JSONData.items[idx].id+ ") identified")

		}

		// irrespective of the gateway filtering note the gateway name
		if (!CompleteGatewayList.contains(name)) 
		{
			CompleteGatewayList.add (name)
		}	
	}

	if (DisplayAll){println ("Found:"+gatewayIds.toString())}
	return gatewayIds.toString()
}

// derives the header information from a query result
String createCSVHeaderRow (Object jsonObj, String label)
{
	StringBuffer sb = new StringBuffer()

 if (DisplayAll){println ("row obj " + rowName + ":\n" +new JsonBuilder(jsonObj).toPrettyString())}

	sb.append (label)
	if (jsonObj != null)
	{

		for (int idx = 0; idx < jsonObj.count; idx++)
		{
			sb.append(SEP)
			sb.append (jsonObj.items[idx].start_ts)
		}
	}

return sb.toString()
}

// this does assume we haven't undeployed the API during the reporting period
String createCSVRow (Object jsonObj, String rowName, int maxValues)
{
	StringBuffer sb = new StringBuffer()

 	if (DisplayAll){println ("row obj " + rowName + ":\n" +new JsonBuilder(jsonObj).toPrettyString())}

	sb.append (rowName)
	if (jsonObj != null)
	{
		int initial = 0
		int subtotalCalls = 0

		if (jsonObj.count > maxValues)
		{
			// if there are more data items in the resultset retrieved than expected -
			// just grab the latest values by moving the array index up
			initial = jsonObj.count - maxValues
		}
		else if (jsonObj.count < maxValues)
		{
			// pad the string buffer with 0 values
			for (int padIdx = 0; padIdx < (maxValues - jsonObj.count); padIdx++)
			{
				sb.append(",0")
			}
		}
		for (int idx = initial; idx < jsonObj.count; idx++)
		{
			sb.append(SEP)
			sb.append (jsonObj.items[idx].measure)

			// capture the total number of API calls
			if (jsonObj.items[idx].measure != null)
			{
				subtotalCalls = subtotalCalls + jsonObj.items[idx].measure.toInteger()
			}

		}

		println ("Total call count for " + rowName + "="+ subtotalCalls)
		totalAPICalls += subtotalCalls

	}
	return sb.toString()
}
//==================================================
// main

		File file = new File(ReportFileName)

		if (file.exists())
		{
			file.delete()
			if (DisplayAll){println ("deleted old version of " + ReportFileName)}
		}
		file.createNewFile()

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

			gatewayIds = getGatewayIds (svr, authString, LogicalGateway)

			String dataType = AppDataTypeLabel
			String timeQuantity= ReportDuration30DayLabel
			String timeUnit = DAY
			String idParam = "apiIds"
			ArrayList trackerList

			def groupIds = "100"

			Boolean HeaderRow = true

			switch (ListType)
			{
				case AppsList:
				dataType = AppDataTypeLabel
				trackerList = CompleteAppsList
				idParam = "appIds"
				break

				case APIsList:
				dataType = ApiDataTypeLabel
				trackerList = CompleteAPIList
				idParam = "apiIds"
				break

				default:
				println ("Unexpected option")
			}

			switch (ReportDurationId)
			{
				case Days365Duration:
					timeUnit = MONTH
					timeQuantity=ReportDurationYearLabel
				break

				case Days30Duration:
					timeUnit = DAY
					timeQuantity=ReportDuration30DayLabel
				break

				case Days7Duration:
					timeUnit = DAY
					timeQuantity=ReportDuration7DayLabel

				break

				case Days1Duration:
					timeUnit = HOUR
					timeQuantity=ReportDuration1DayLabel
				break

				default:
				println ("Unknown interval defined")
			}

			int colCount = 0
			dataSet = getIds (ListType, authString, svr, trackerList)

			if (DisplayAll){println ("Gateways:"+gatewayIds+"| grouping by:"+DataGrouping + "| for period of " + timeQuantity + " |  unit " + timeUnit)}

			// iterate over this call for each API or App
			dataSet.each {id, name ->
				// need to go look up the descriptions
				String query = null

				query= svr + "/apiplatform/analytics/v1/timeSeries/requests/all"+"?gatewayIds="+gatewayIds+"&groupBys"+DataGrouping + "&timeSetting="+timeQuantity+ "&timeGroupSize=1&timeUnit="+timeUnit+"&"+idParam+"="+id

				def queryURL = new URL(query).openConnection()
				queryURL.setRequestProperty(Authorization, authString)
				def JSONData = new JsonSlurper().parse(queryURL.getInputStream())

				if (HeaderRow)
				{
					if (JSONData.count > 0)
					{
						line = createCSVHeaderRow (JSONData, dataType)
						colCount = line.count(SEP)

						file.append (line+"\n")
						if (DisplayAll){println ("Header created:"+line)}
						HeaderRow = false
					}
				}

				row = createCSVRow (JSONData, name, colCount)

				if (DisplayAll){println (row)}
				file.append (row + "\n")
			} // end of each

			switch (ListType)
			{
				case AppsList:
					// if the lookup is by App, get the APIs
					getIds (APIsList, authString, svr, CompleteAPIList)
				break

				case APIsList:
					// if the lookup is by api, get the apps
					getIds (AppsList, authString, svr, CompleteAppsList)
				break

				default:
				println ("Unexpected option")
			}
			outputTotals (timeQuantity)
		}
		catch (Exception err)
		{
			err.printStackTrace()
		}

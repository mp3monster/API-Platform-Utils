# API Policy Quality Checker



## Introduction

TBD

Background to this utility can be found at  [http://blog.mp3monster.org/2019/12/14/development-stan…for-api-policies/](https://mp3muncher.wordpress.com/?p=4320&preview=true)



## Properties File Values

| Name                     | Required          | Explanation                                                  | Example                                                      |
| ------------------------ | ----------------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| server                   | Y                 | The address of the API Platform CS being used                | https://YourServiceDomain.apiplatform.ocp.oraclecloud.com    |
| IDCS                     | Y (if using IDCS) | Address of the Identity Cloud Service being used - we use to get the OAuth token | https://idcs-YourServiceDomain.identity.oraclecloud.com/oauth2/v1/token |
| scope                    | Y (if using IDCS) | Scope of the token                                           | https://YourServiceDomain.apiplatform.ocp.oraclecloud.com:443.apiplatform offline_access |
| username                 | Y                 | Username with the appropriate privileges (password is included in the commandline) | myUsername                                                   |
| display                  | N                 | Verbose or not - accepted values are - t \| f \| y \| n \| true \| false \| yes \| no recommend using f | f                                                            |
| reportFilename           | Y                 | The filename to write the details to e.g. myReport.txt       | myReport.txt                                                 |
| APINameExpr              | N                 | Java regular expression to validate API names against        | (myPrefix1\|yourPrefix) - [\\\w\\\s]+                        |
| PlanNameExpr             | N                 | Java regular expression to validate plan names against       | (myPrefix1\|yourPrefix)                                      |
| AppNameExpr              | N                 | Java regular expression to validate Application names against | [\\\\w\\\\s]+                                                |
| ServiceNameExpr          | N                 | Java regular expression to validate service names against    |                                                              |
| RequiredRequestPolicies  | N                 | The names of the policies to be used as a comma separated list. Additional policies used not in the list won't create any alarms. Note that Oracle typically prefixes with o: this can be omitted the list includes: - InterfaceFiltering, Logging, InterfaceFiltering, KeyValidation | GatewayBasedRouting, Logging                                 |
| RequiredResponsePolicies | N                 | The names of the policies to be used as a comma separated list. Additional policies used not in the list won't create any alarms. Note that Oracle typically prefixes with o: this can be omitted the list includes: - InterfaceFiltering, Logging, InterfaceFiltering, KeyValidation | Logging                                                      |

When a property is not defined, then associated checks will not be applied.
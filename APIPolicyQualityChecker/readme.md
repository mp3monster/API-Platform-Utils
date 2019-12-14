# API Policy Quality Checker



## Introduction

TBD

Background to this utility can be found at  [http://blog.mp3monster.org/2019/12/14/development-stan…for-api-policies/](https://mp3muncher.wordpress.com/?p=4320&preview=true)



## Properties File Values

| Name                     | Required          | Explanation | Example |
| ------------------------ | ----------------- | ----------- | ------- |
| server                   | Y                 |             |         |
| IDCS                     | Y (if using IDCS) |             |         |
| scope                    | Y (if using IDCS) |             |         |
| username                 | Y                 |             |         |
| display                  | N                 |             |         |
| reportFilename           | Y                 |             |         |
| APINameExpr              | N                 |             |         |
| PlanNameExpr             | N                 |             |         |
| AppNameExpr              | N                 |             |         |
| ServiceNameExpr          | N                 |             |         |
| RequiredRequestPolicies  | N                 |             |         |
| RequiredResponsePolicies | N                 |             |         |

When a property is not defined, then associated checks will not be applied.
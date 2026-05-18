from __future__ import annotations

import os

import aws_cdk as cdk
from aws_cdk import (
    Duration,
    Fn,
    Stack,
    aws_iam as iam,
    aws_lambda as lambda_,
)
from constructs import Construct

_LAMBDA_CODE_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "lambda", "cloudtrail_tool")

# Powertools for AWS Lambda (Python 3.11) public layer — account 017000801446.
# Version pinned to a recent stable release; bump via PR when newer layers ship.
_POWERTOOLS_LAYER_ARN = Fn.sub(
    "arn:aws:lambda:${AWS::Region}:017000801446:layer:AWSLambdaPowertoolsPythonV3-python311:17"
)


class LambdaStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs: object) -> None:
        super().__init__(scope, construct_id, **kwargs)

        role = iam.Role(
            self,
            "CloudTrailToolRole",
            role_name="cloudtrail-tool-lambda-role",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
        )

        # Statement 1: CloudTrail LookupEvents — no resource-level constraint exists.
        role.add_to_policy(
            iam.PolicyStatement(
                sid="CloudTrailLookup",
                actions=["cloudtrail:LookupEvents"],
                resources=["*"],
            )
        )

        # Statement 2: CloudTrail Lake queries — scoped to event data stores only.
        role.add_to_policy(
            iam.PolicyStatement(
                sid="CloudTrailLakeQuery",
                actions=[
                    "cloudtrail-data:StartQuery",
                    "cloudtrail-data:GetQueryResults",
                    "cloudtrail-data:DescribeQuery",
                    "cloudtrail-data:CancelQuery",
                ],
                resources=["arn:aws:cloudtrail:*:*:eventdatastore/*"],
            )
        )

        powertools_layer = lambda_.LayerVersion.from_layer_version_arn(
            self,
            "PowertoolsLayer",
            _POWERTOOLS_LAYER_ARN,
        )

        fn = lambda_.Function(
            self,
            "CloudTrailToolFunction",
            runtime=lambda_.Runtime.PYTHON_3_11,
            handler="handler.handler",
            code=lambda_.Code.from_asset(_LAMBDA_CODE_PATH),
            memory_size=512,
            timeout=Duration.seconds(60),
            role=role,
            layers=[powertools_layer],
        )

        # Statement 3: CloudWatch Logs — scoped to the function's own log group.
        role.add_to_policy(
            iam.PolicyStatement(
                sid="CloudWatchLogs",
                actions=[
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                ],
                resources=[
                    fn.log_group.log_group_arn,
                    f"{fn.log_group.log_group_arn}:log-stream:*",
                ],
            )
        )

        cdk.CfnOutput(
            self,
            "LambdaArn",
            value=fn.function_arn,
            export_name="CloudTrailToolStack-lambda-arn",
        )
        cdk.CfnOutput(
            self,
            "LambdaName",
            value=fn.function_name,
            export_name="CloudTrailToolStack-lambda-name",
        )

from __future__ import annotations

import aws_cdk as cdk

from stacks.lambda_stack import LambdaStack

app = cdk.App()

stack = LambdaStack(app, "CloudTrailToolStack")
cdk.Tags.of(stack).add("Project", "cloudtrail-agent")

app.synth()

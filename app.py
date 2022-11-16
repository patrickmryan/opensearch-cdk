#!/usr/bin/env python3
import os

import aws_cdk as cdk

from oss.oss_stack import OssStack


app = cdk.App()
OssStack(
    app,
    "OssStack",
    env=cdk.Environment(
        account=os.getenv("CDK_DEFAULT_ACCOUNT"), region=os.getenv("CDK_DEFAULT_REGION")
    ),
)

app.synth()

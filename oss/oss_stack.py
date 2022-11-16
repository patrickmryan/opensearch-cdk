from aws_cdk import (
    Duration,
    Stack,
    SecretValue,
    CfnOutput,
    aws_opensearchservice as oss,
    aws_iam as iam,
    aws_ec2 as ec2,
)
from constructs import Construct


class OssStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        permissions_boundary_policy_arn = self.node.try_get_context(
            "PermissionsBoundaryPolicyArn"
        )
        if not permissions_boundary_policy_arn:
            permissions_boundary_policy_name = self.node.try_get_context(
                "PermissionsBoundaryPolicyName"
            )
            if permissions_boundary_policy_name:
                permissions_boundary_policy_arn = self.format_arn(
                    service="iam",
                    region="",
                    account=self.account,
                    resource="policy",
                    resource_name=permissions_boundary_policy_name,
                )

        if permissions_boundary_policy_arn:
            policy = iam.ManagedPolicy.from_managed_policy_arn(
                self, "PermissionsBoundary", permissions_boundary_policy_arn
            )
            iam.PermissionsBoundary.of(self).apply(policy)

        vpc_name = self.node.try_get_context("VpcName")
        vpc = ec2.Vpc.from_lookup(self, "Vpc", tags={"Name": vpc_name})

        security_group_names = self.node.try_get_context("SecurityGroupNames")

        domain_security = oss.AdvancedSecurityOptions(
            master_user_name="master",
            master_user_password=SecretValue.unsafe_plain_text("Mast3r!!"),
        )

        domain = oss.Domain(
            self,
            "OssDomain",
            version=oss.EngineVersion.OPENSEARCH_1_3,
            ebs=oss.EbsOptions(volume_size=100),
            node_to_node_encryption=True,
            encryption_at_rest=oss.EncryptionAtRestOptions(enabled=True),
            vpc=vpc,
            security_groups=[
                ec2.SecurityGroup.from_lookup_by_name(self, "sg" + name, name, vpc)
                for name in security_group_names
            ],
            capacity=oss.CapacityConfig(
                data_node_instance_type="t3.small.search", data_nodes=1
            ),
            enforce_https=True,
            fine_grained_access_control=domain_security,
        )

        # CfnOutput(
        #     self,
        #     "MasterPassword",
        #     value=domain_security.master_user_password.unsafePlainText,
        # )

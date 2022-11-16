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
import boto3


class OssStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        self.ec2_resource = boto3.resource("ec2")

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

        vpc_resource = self.ec2_resource.Vpc(vpc.vpc_id)

        subnets = self.get_subnets_tagged(
            vpc=vpc_resource,
            tag_key="SubnetType",
            tag_value="private",
            prefix="Data",
        )

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
            # vpc_subnets={ subnet.subnet_id: subnet.subnet_id for subnet in subnets },
            vpc_subnets=[ec2.SubnetSelection(subnets=subnets)],
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

    def get_subnets_tagged(
        self, vpc=None, tag_key=None, tag_value=None, min_addresses=0, prefix=""
    ):

        subnets = []
        for subnet in vpc.subnets.all():
            tags = {tag["Key"]: tag["Value"] for tag in subnet.tags}  # dict-ify

            if min_addresses and subnet.available_ip_address_count < min_addresses:
                continue

            if tags[tag_key] != tag_value:
                continue

            subnets.append(
                ec2.Subnet.from_subnet_id(
                    self,
                    prefix + subnet.subnet_id,
                    subnet.subnet_id,
                )
            )

        return subnets

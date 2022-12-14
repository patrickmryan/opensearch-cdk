from aws_cdk import (
    Stack,
    SecretValue,
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

        cidr_range = self.node.try_get_context("CidrRange")
        if not cidr_range:
            cidr_range = "10.0.0.0/16"

        subnet_configs = []
        subnet_cidr_mask = 24

        subnet_configs.append(
            ec2.SubnetConfiguration(
                name="Private",
                subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS,
                cidr_mask=subnet_cidr_mask,
            )
        )
        subnet_configs.append(
            ec2.SubnetConfiguration(
                name="Public",
                subnet_type=ec2.SubnetType.PUBLIC,
                cidr_mask=subnet_cidr_mask,
            )
        )

        vpc = ec2.Vpc(
            self,
            "Vpc",
            ip_addresses=ec2.IpAddresses.cidr(cidr_range),
            enable_dns_hostnames=True,
            enable_dns_support=True,
            max_azs=2,
            nat_gateway_provider=ec2.NatProvider.gateway(),
            subnet_configuration=subnet_configs,
        )

        security_group = ec2.SecurityGroup(self, "OssDomainSG", vpc=vpc)
        security_group.add_ingress_rule(
            ec2.Peer.ipv4(cidr_range), ec2.Port.all_traffic()
        )

        domain_security = oss.AdvancedSecurityOptions(
            master_user_name="master",
            master_user_password=SecretValue.unsafe_plain_text("Mast3r!!"),
        )

        # aws iam create-service-linked-role --aws-service-name opensearchservice.amazonaws.com

        domain = oss.Domain(
            self,
            "OssDomain",
            version=oss.EngineVersion.open_search("2.3"),  #    OPENSEARCH_1_3,
            ebs=oss.EbsOptions(volume_size=100),
            node_to_node_encryption=True,
            encryption_at_rest=oss.EncryptionAtRestOptions(enabled=True),
            vpc=vpc,
            vpc_subnets=[
                ec2.SubnetSelection(
                    subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS,
                    availability_zones=vpc.availability_zones[0:1],
                )
            ],
            security_groups=[security_group],
            capacity=oss.CapacityConfig(
                data_node_instance_type="t3.small.search", data_nodes=1
            ),
            tls_security_policy=oss.TLSSecurityPolicy.TLS_1_2,
            enforce_https=True,
            fine_grained_access_control=domain_security,
        )

        domain.add_access_policies(
            iam.PolicyStatement(
                principals=[iam.AnyPrincipal()],
                actions=["es:*"],
                resources=[f"{domain.domain_arn}/*"],
            )
        )

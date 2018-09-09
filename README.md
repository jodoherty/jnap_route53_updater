# Route53 updater using Linksys JNAP

This Python script runs as a service, querying the local Linksys WiFi router
for the current IP address which it then uses to update entries in Route53
whenever it changes.


```
usage: update_dns.py [-h] --host HOST [--router-ip ROUTER_IP]
                     [--router-user ROUTER_USER]
                     [--router-password ROUTER_PASSWORD] --hosted-zone-id
                     HOSTED_ZONE_ID [--region REGION] --aws-access-key-id
                     AWS_ACCESS_KEY_ID --aws-secret-access-key
                     AWS_SECRET_ACCESS_KEY

Route 53 dynamic DNS updater

optional arguments:
  -h, --help            show this help message and exit
  --host HOST           The hostname to update
  --router-ip ROUTER_IP
                        The router IP address
  --router-user ROUTER_USER
                        The router username
  --router-password ROUTER_PASSWORD
                        The router password
  --hosted-zone-id HOSTED_ZONE_ID
                        The Route 53 Hosted Zone ID
  --region REGION       The AWS Region
  --aws-access-key-id AWS_ACCESS_KEY_ID
                        The AWS Access Key ID
  --aws-secret-access-key AWS_SECRET_ACCESS_KEY
                        The AWS Secret Access Key
```

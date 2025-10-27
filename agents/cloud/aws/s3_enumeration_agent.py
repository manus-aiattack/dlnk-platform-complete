"""AWS S3 Enumeration Agent"""
import asyncio, boto3, os
from typing import Dict, Any
from core.base_agent import BaseAgent
from core.agent_data import AgentData

class AWSS3EnumerationAgent(BaseAgent):
    def __init__(self):
        super().__init__(name="AWSS3EnumerationAgent", description="Enumerate and exploit S3 buckets", version="1.0.0")
        self.output_dir = "workspace/aws_s3"
        os.makedirs(self.output_dir, exist_ok=True)
    
    async def run(self, strategy: Dict[str, Any]) -> AgentData:
        try:
            aws_access_key = strategy.get('aws_access_key_id', os.getenv('AWS_ACCESS_KEY_ID', ""))
            aws_secret_key = strategy.get('aws_secret_access_key', os.getenv('AWS_SECRET_ACCESS_KEY', ""))
            region = strategy.get('region', 'us-east-1')
            
            s3 = boto3.client('s3', aws_access_key_id=aws_access_key, aws_secret_access_key=aws_secret_key, region_name=region)
            
            buckets = s3.list_buckets()['Buckets']
            results = []
            
            for bucket in buckets:
                bucket_name = bucket['Name']
                try:
                    acl = s3.get_bucket_acl(Bucket=bucket_name)
                    public = any(g['Grantee'].get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers' for g in acl['Grants'])
                    results.append({'bucket': bucket_name, 'public': public, 'acl': acl})
                except Exception as e:
                    results.append({'bucket': bucket_name, 'error': 'Access denied'})
            
            return AgentData(success=True, data={'buckets': results, 'count': len(results)})
        except Exception as e:
            return AgentData(success=False, errors=[str(e)])

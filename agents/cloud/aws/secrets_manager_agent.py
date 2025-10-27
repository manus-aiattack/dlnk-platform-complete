"""AWS Secrets Manager Agent"""
import asyncio, boto3
from typing import Dict, Any
from core.base_agent import BaseAgent
from core.agent_data import AgentData

class AWSSecretsManagerAgent(BaseAgent):
    def __init__(self):
        super().__init__(name="AWSSecretsManagerAgent", description="Extract AWS Secrets Manager secrets", version="1.0.0")
    
    async def run(self, strategy: Dict[str, Any]) -> AgentData:
        try:
            secrets_client = boto3.client('secretsmanager')
            secrets_list = secrets_client.list_secrets()['SecretList']
            
            extracted = []
            for secret in secrets_list:
                try:
                    value = secrets_client.get_secret_value(SecretId=secret['Name'])
                    extracted.append({'name': secret['Name'], 'value': value.get('SecretString', value.get('SecretBinary'))})
                except Exception as e:
                    extracted.append({'name': secret['Name'], 'error': 'Access denied'})
            
            return AgentData(success=True, data={'secrets': extracted, 'count': len(extracted)})
        except Exception as e:
            return AgentData(success=False, errors=[str(e)])

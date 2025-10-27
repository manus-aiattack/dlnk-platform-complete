import requests
import json
from typing import List, Dict, Any, Optional
from pydantic import BaseModel

class GraphQLType(BaseModel):
    """Data model for a GraphQL type."""
    kind: str
    name: Optional[str] = None
    ofType: Optional[Any] = None

class GraphQLField(BaseModel):
    """Data model for a GraphQL field."""
    name: str
    description: Optional[str] = None
    args: List[Dict[str, Any]] = []
    type: GraphQLType

class GraphQLIntrospector:
    """
    Introspects a GraphQL API to discover its schema.
    """

    def __init__(self, endpoint_url: str):
        """
        Initializes the introspector with the GraphQL endpoint URL.

        Args:
            endpoint_url: The URL of the GraphQL endpoint.
        """
        self.endpoint_url = endpoint_url
        self.schema = self._get_schema()

    def _get_schema(self) -> Dict[str, Any]:
        """
        Performs the introspection query to get the GraphQL schema.
        """
        introspection_query = """
            query IntrospectionQuery {
                __schema {
                    queryType { name }
                    mutationType { name }
                    subscriptionType { name }
                    types {
                        ...FullType
                    }
                    directives {
                        name
                        description
                        locations
                        args {
                            ...InputValue
                        }
                    }
                }
            }

            fragment FullType on __Type {
                kind
                name
                description
                fields(includeDeprecated: true) {
                    name
                    description
                    args {
                        ...InputValue
                    }
                    type {
                        ...TypeRef
                    }
                    isDeprecated
                    deprecationReason
                }
                inputFields {
                    ...InputValue
                }
                interfaces {
                    ...TypeRef
                }
                enumValues(includeDeprecated: true) {
                    name
                    description
                    isDeprecated
                    deprecationReason
                }
                possibleTypes {
                    ...TypeRef
                }
            }

            fragment InputValue on __InputValue {
                name
                description
                type { ...TypeRef }
                defaultValue
            }

            fragment TypeRef on __Type {
                kind
                name
                ofType {
                    kind
                    name
                    ofType {
                        kind
                        name
                        ofType {
                            kind
                            name
                            ofType {
                                kind
                                name
                                ofType {
                                    kind
                                    name
                                    ofType {
                                        kind
                                        name
                                    }
                                }
                            }
                        }
                    }
                }
            }
        """
        try:
            response = requests.post(self.endpoint_url, json={"query": introspection_query})
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"Error getting schema: {e}")
            return {{}}

    def get_queries(self) -> List[GraphQLField]:
        """
        Returns a list of all queries from the schema.
        """
        queries = []
        query_type_name = self.schema.get("data", {{}}).get("__schema", {{}}).get("queryType", {{}}).get("name")
        if query_type_name:
            for type_info in self.schema.get("data", {{}}).get("__schema", {{}}).get("types", []):
                if type_info.get("name") == query_type_name:
                    for field in type_info.get("fields", []):
                        queries.append(GraphQLField(**field))
        return queries

    def get_mutations(self) -> List[GraphQLField]:
        """
        Returns a list of all mutations from the schema.
        """
        mutations = []
        mutation_type_name = self.schema.get("data", {{}}).get("__schema", {{}}).get("mutationType", {{}}).get("name")
        if mutation_type_name:
            for type_info in self.schema.get("data", {{}}).get("__schema", {{}}).get("types", []):
                if type_info.get("name") == mutation_type_name:
                    for field in type_info.get("fields", []):
                        mutations.append(GraphQLField(**field))
        return mutations

class GraphQLFuzzer:
    """
    Generates fuzzing variations for GraphQL queries and mutations.
    """

    def __init__(self, introspector: GraphQLIntrospector):
        """
        Initializes the fuzzer with a GraphQLIntrospector instance.

        Args:
            introspector: An instance of GraphQLIntrospector.
        """
        self.introspector = introspector

    def _generate_payloads(self, arg_type: str) -> List[Any]:
        """
        Generates a list of fuzzing payloads for a given argument type.
        """
        if "String" in arg_type:
            return ["'", '"', '`', '\\', '<', '>', ' OR 1=1 --', ' OR 1=1 #', ' OR 1=1 /*', " OR 'a'='a"]
        elif "Int" in arg_type:
            return [0, -1, 1, 99999999999999999999, -99999999999999999999]
        elif "Boolean" in arg_type:
            return [True, False]
        else:
            return []

    def fuzz_field(self, field: GraphQLField) -> List[Dict[str, Any]]:
        """
        Generates fuzzing queries or mutations for a given field.
        """
        fuzz_requests = []
        for arg in field.args:
            arg_name = arg["name"]
            arg_type = arg["type"]["name"] if arg["type"]["name"] else arg["type"]["ofType"]["name"]
            payloads = self._generate_payloads(arg_type)
            for payload in payloads:
                query = f"""
                    mutation {{
                        {field.name}({arg_name}: "{payload}") {{
                            # Add fields to return here
                        }}
                    }}
                """
                if self.introspector.schema.get("data", {{}}).get("__schema", {{}}).get("queryType", {{}}).get("name") and field in self.introspector.get_queries():
                    query = f"""
                        query {{
                            {field.name}({arg_name}: "{payload}") {{
                                # Add fields to return here
                            }}
                        }}
                    """
                fuzz_requests.append({"query": query})
        return fuzz_requests
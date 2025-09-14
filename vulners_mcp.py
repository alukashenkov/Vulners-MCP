import json
import logging
import os
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from mcp.server.fastmcp import FastMCP
import httpx
from pydantic import BaseModel, Field, field_validator

# Configure logging based on DEBUG environment variable
debug_mode = os.getenv("DEBUG", "false").lower() in ("true", "1", "yes", "on")
logging_level = logging.DEBUG if debug_mode else logging.INFO
logging.basicConfig(level=logging_level, format='%(asctime)s - %(levelname)s - %(message)s')

# Initialize FastMCP server
mcp = FastMCP("Vulners-MCP", stateless_http=False)

# Global cache for CAPEC ID to name mapping
_capec_cache = None

def _safe_pydantic_conversion(model_class, data: Optional[dict], fallback_error: str = "Validation failed", cve_id: Optional[str] = None, bulletin_id: Optional[str] = None):
    """Safely convert dictionary data to Pydantic model with error handling."""
    try:
        if data is None:
            logging.error(f"Received None data for {model_class.__name__}")
            # Return a basic error response with available IDs
            # Handle different model types based on class name
            class_name = getattr(model_class, '__name__', '')
            if class_name == 'CveInfoOutput':
                return model_class(
                    success=False,
                    error=f"{fallback_error}: Received None data",
                    cve_id=cve_id if cve_id else "UNKNOWN"
                )
            elif class_name == 'BulletinInfoOutput':
                return model_class(
                    success=False,
                    error=f"{fallback_error}: Received None data",
                    bulletin_id=bulletin_id if bulletin_id else "UNKNOWN"
                )
            else:
                # Generic fallback - this shouldn't happen but just in case
                return None
        
        return model_class(**data)
    except Exception as e:
        logging.error(f"Pydantic validation failed for {model_class.__name__}: {e}")
        # Return a basic error response
        if model_class == CveInfoOutput:
            if cve_id:
                return model_class(
                    success=False,
                    error=f"{fallback_error}: {str(e)}",
                    cve_id=cve_id
                )
            else:
                return model_class(
                    success=False,
                    error=f"{fallback_error}: {str(e)}",
                    cve_id="UNKNOWN"
                )
        elif model_class == BulletinInfoOutput:
            if bulletin_id:
                return model_class(
                    success=False,
                    error=f"{fallback_error}: {str(e)}",
                    bulletin_id=bulletin_id
                )
            else:
                return model_class(
                    success=False,
                    error=f"{fallback_error}: {str(e)}",
                    bulletin_id="UNKNOWN"
                )
        return None

# Pydantic Models for Input Validation
class CveInfoInput(BaseModel):
    """Input model for CVE information requests."""
    cve_id: str = Field(..., description="CVE ID in format CVE-YYYY-NNNN")
    
    @field_validator('cve_id')
    @classmethod
    def validate_cve_format(cls, v):
        if not re.match(r'^CVE-\d{4}-\d{4,}$', v, re.IGNORECASE):
            raise ValueError(f"Invalid CVE format: {v}. Expected format: CVE-YYYY-NNNN")
        return v.upper()

class BulletinInfoInput(BaseModel):
    """Input model for bulletin information requests."""
    bulletin_id: str = Field(..., description="Security bulletin ID (GHSA, RHSA, NASL, advisories, etc.)")

# Pydantic Models for Output Validation
class CoreInfo(BaseModel):
    """Core information about a vulnerability."""
    id: str = Field(..., description="Vulnerability identifier")
    published: Optional[str] = Field(None, description="Publication date")
    description: Optional[str] = Field(None, description="Vulnerability description")
    title: Optional[str] = Field(None, description="Vulnerability title")
    type: Optional[str] = Field(None, description="Vulnerability type")
    href: Optional[str] = Field(None, description="Reference link")

class CvssMetrics(BaseModel):
    """CVSS metrics information."""
    version: str = Field(..., description="CVSS version")
    source: str = Field(..., description="CVSS source")
    base_score: float = Field(..., description="CVSS base score")
    base_severity: str = Field(..., description="CVSS base severity")
    vector_string: str = Field(..., description="CVSS vector string")
    v4_fields: Optional[Dict[str, Any]] = Field(None, description="CVSS v4 specific fields")

class SsvcMetrics(BaseModel):
    """SSVC metrics information."""
    role: str = Field(..., description="SSVC role")
    version: str = Field(..., description="SSVC version")
    options: Optional[List[str]] = Field(None, description="SSVC options")

class EpssScore(BaseModel):
    """EPSS score information."""
    score: float = Field(..., description="EPSS score")
    percentile: float = Field(..., description="EPSS percentile")
    date: str = Field(..., description="EPSS date")

class TaxonomyMapping(BaseModel):
    """Taxonomy mapping information."""
    taxonomy: str = Field(..., description="Taxonomy name")
    entry_id: Optional[str] = Field(None, description="Taxonomy entry ID")
    entry_name: Optional[str] = Field(None, description="Taxonomy entry name")

class CapecData(BaseModel):
    """CAPEC attack pattern data."""
    id: str = Field(..., description="CAPEC ID")
    name: str = Field(..., description="CAPEC name")
    taxonomy_mappings: List[TaxonomyMapping] = Field(default_factory=list, description="Taxonomy mappings")

class RelatedCapec(BaseModel):
    """Related CAPEC information."""
    capec_ids: List[str] = Field(..., description="List of CAPEC IDs")
    capec_data: List[CapecData] = Field(..., description="CAPEC data")

class Consequences(BaseModel):
    """CWE consequences information."""
    scopes: List[str] = Field(default_factory=list, description="Affected scopes")
    impacts: List[str] = Field(default_factory=list, description="Impact types")

class CweConsequence(BaseModel):
    """CWE consequence information."""
    cwe_id: str = Field(..., description="CWE ID")
    name: str = Field(..., description="CWE name")
    consequences: Optional[Consequences] = Field(None, description="CWE consequences")
    related_capec: Optional[RelatedCapec] = Field(None, description="Related CAPEC information")

class ShadowserverItem(BaseModel):
    """Shadowserver exploitation item."""
    source: str = Field(..., description="Shadowserver source")

class ExploitationStatus(BaseModel):
    """Exploitation status information."""
    wild_exploited: bool = Field(..., description="Whether exploited in the wild")
    sources: List[str] = Field(default_factory=list, description="Exploitation sources")
    shadowserver_items: Optional[List[ShadowserverItem]] = Field(None, description="Shadowserver items")

class RelatedDocument(BaseModel):
    """Related document information."""
    id: str = Field(..., description="Document ID")
    type: str = Field(..., description="Document type")
    title: str = Field(..., description="Document title")
    published: Optional[str] = Field(None, description="Publication date")
    view_count: Optional[int] = Field(None, description="View count")
    link: Optional[str] = Field(None, description="Document link")

class CveInfoOutput(BaseModel):
    """Output model for CVE information responses."""
    success: bool = Field(..., description="Whether the request was successful")
    error: Optional[str] = Field(None, description="Error message if unsuccessful")
    cve_id: str = Field(..., description="CVE ID")
    core_info: Optional[CoreInfo] = Field(None, description="Core vulnerability information")
    cvss_metrics: Optional[List[CvssMetrics]] = Field(None, description="CVSS metrics")
    ssvc_metrics: Optional[List[SsvcMetrics]] = Field(None, description="SSVC metrics")
    epss_score: Optional[EpssScore] = Field(None, description="EPSS score")
    cwe_classifications: Optional[List[str]] = Field(None, description="CWE classifications")
    cwe_consequences: Optional[List[CweConsequence]] = Field(None, description="CWE consequences")
    exploitation_status: Optional[ExploitationStatus] = Field(None, description="Exploitation status")
    affected_products: Optional[List[str]] = Field(None, description="Affected products")
    references: Optional[List[str]] = Field(None, description="References")
    related_cves: Optional[List[str]] = Field(None, description="Related CVEs")
    solutions: Optional[List[str]] = Field(None, description="Solutions")
    workarounds: Optional[List[str]] = Field(None, description="Workarounds")
    related_documents: Optional[List[RelatedDocument]] = Field(None, description="Related documents")

class BulletinInfoOutput(BaseModel):
    """Output model for bulletin information responses."""
    success: bool = Field(..., description="Whether the request was successful")
    error: Optional[str] = Field(None, description="Error message if unsuccessful")
    bulletin_id: str = Field(..., description="Bulletin ID")
    core_info: Optional[CoreInfo] = Field(None, description="Core bulletin information")
    references: Optional[List[str]] = Field(None, description="References")
    related_cves: Optional[List[str]] = Field(None, description="Related CVEs")

# Legacy JSON Schema definitions for CrewAI optimization (kept for backward compatibility)
CVE_INFO_INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "cve_id": {
            "type": "string",
            "description": "CVE ID in format CVE-YYYY-NNNN",
            "pattern": "^CVE-\\d{4}-\\d{4,}$"
        }
    },
    "required": ["cve_id"]
}

CVE_INFO_OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "success": {"type": "boolean"},
        "error": {"type": "string"},
        "cve_id": {"type": "string"},
        "core_info": {
            "type": "object",
            "properties": {
                "id": {"type": "string"},
                "published": {"type": "string"},
                "description": {"type": "string"}
            }
        },
        "cvss_metrics": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "version": {"type": "string"},
                    "source": {"type": "string"},
                    "base_score": {"type": "number"},
                    "base_severity": {"type": "string"},
                    "vector_string": {"type": "string"},
                    "v4_fields": {"type": "object"}
                }
            }
        },
        "epss_score": {
            "type": "object",
            "properties": {
                "score": {"type": "number"},
                "percentile": {"type": "number"},
                "date": {"type": "string"}
            }
        },
        "cwe_classifications": {
            "type": "array",
            "items": {"type": "string"}
        },
        "cwe_consequences": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "cwe_id": {"type": "string"},
                    "name": {"type": "string"},
                    "consequences": {
                        "type": "object",
                        "properties": {
                            "scopes": {"type": "array", "items": {"type": "string"}},
                            "impacts": {"type": "array", "items": {"type": "string"}}
                        }
                    },
                    "related_capec": {
                        "type": "object",
                        "properties": {
                            "capec_ids": {"type": "array", "items": {"type": "string"}},
                            "capec_data": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "id": {"type": "string"},
                                        "name": {"type": "string"},
                                        "taxonomy_mappings": {"type": "array"}
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
        "exploitation_status": {
            "type": "object",
            "properties": {
                "wild_exploited": {"type": "boolean"},
                "sources": {"type": "array", "items": {"type": "string"}},
                "shadowserver_items": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "source": {"type": "string"}
                        }
                    }
                }
            }
        },
        "affected_products": {
            "type": "array",
            "items": {"type": "string"}
        },
        "references": {
            "type": "array",
            "items": {"type": "string"}
        },
        "related_cves": {
            "type": "array",
            "items": {"type": "string"}
        },
        "solutions": {
            "type": "array",
            "items": {"type": "string"}
        },
        "workarounds": {
            "type": "array",
            "items": {"type": "string"}
        },
        "related_documents": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "type": {"type": "string"},
                    "title": {"type": "string"},
                    "published": {"type": "string"},
                    "view_count": {"type": "integer"},
                    "link": {"type": "string"}
                }
            }
        }
    }
}

BULLETIN_INFO_INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "bulletin_id": {
            "type": "string",
            "description": "Security bulletin ID (GHSA, RHSA, NASL, advisories, etc.)"
        }
    },
    "required": ["bulletin_id"]
}

BULLETIN_INFO_OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "success": {"type": "boolean"},
        "error": {"type": "string"},
        "bulletin_id": {"type": "string"},
        "core_info": {
            "type": "object",
            "properties": {
                "id": {"type": "string"},
                "title": {"type": "string"},
                "type": {"type": "string"},
                "published": {"type": "string"},
                "href": {"type": "string"},
                "description": {"type": "string"}
            }
        },
        "references": {
            "type": "array",
            "items": {"type": "string"}
        },
        "related_cves": {
            "type": "array",
            "items": {"type": "string"}
        }
    }
}

def _sanitize_filename(bulletin_id: str) -> str:
    """Sanitizes bulletin ID for use as a filename by removing/replacing invalid characters."""
    # Replace invalid filename characters with underscores
    sanitized = re.sub(r'[<>:"/\\|?*]', '_', bulletin_id)
    # Remove any leading/trailing whitespace and dots
    sanitized = sanitized.strip('. ')
    return sanitized

def _save_debug_output(bulletin_id: str, output: str) -> None:
    """Saves tool output to a debug file when debug mode is enabled."""
    if not debug_mode:
        return
    
    try:
        # Get script directory
        script_dir = Path(__file__).parent
        
        # Create sanitized filename with prefix and .json extension
        filename = f"vulners_mcp_output_{_sanitize_filename(bulletin_id)}.json"
        file_path = script_dir / filename
        
        # Write output to file
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(output)
        
        logging.debug(f"Debug output saved to: {file_path}")
        
    except Exception as e:
        logging.error(f"Failed to save debug output for {bulletin_id}: {e}")

def _load_capec_names() -> dict:
    """Loads CAPEC ID to name and taxonomy mapping from the local 1000.xml file.
    
    Returns a dictionary mapping CAPEC ID strings to attack pattern data including
    name and taxonomy mappings to other security frameworks.
    Uses caching to avoid re-parsing the XML file on every call.
    """
    global _capec_cache
    
    if _capec_cache is not None:
        return _capec_cache
    
    capec_mapping = {}
    
    # Look for 1000.xml in the same directory as this script
    script_dir = Path(__file__).parent
    capec_file = script_dir / "1000.xml"
    
    if not capec_file.exists():
        logging.warning(f"CAPEC taxonomy file not found at {capec_file}")
        _capec_cache = {}
        return _capec_cache
    
    try:
        # Parse the XML file
        tree = ET.parse(capec_file)
        root = tree.getroot()
        
        # Detect namespace from root tag
        namespace = ''
        if '{' in root.tag:
            namespace = root.tag.split('}')[0] + '}'
        
        # Find all Attack_Pattern elements with proper namespace handling
        attack_pattern_tag = f'{namespace}Attack_Pattern'
        taxonomy_mappings_tag = f'{namespace}Taxonomy_Mappings'
        taxonomy_mapping_tag = f'{namespace}Taxonomy_Mapping'
        entry_id_tag = f'{namespace}Entry_ID'
        entry_name_tag = f'{namespace}Entry_Name'
        
        for attack_pattern in root.iter(attack_pattern_tag):
            capec_id = attack_pattern.get('ID')
            capec_name = attack_pattern.get('Name')
            
            if capec_id and capec_name:
                # Initialize CAPEC data structure
                capec_data = {
                    'name': capec_name,
                    'taxonomy_mappings': []
                }
                
                # Extract taxonomy mappings
                taxonomy_mappings_elem = attack_pattern.find(taxonomy_mappings_tag)
                if taxonomy_mappings_elem is not None:
                    for mapping in taxonomy_mappings_elem.findall(taxonomy_mapping_tag):
                        taxonomy_name = mapping.get('Taxonomy_Name')
                        if taxonomy_name:
                            mapping_data = {'taxonomy': taxonomy_name}
                            
                            # Extract Entry_ID if present
                            entry_id_elem = mapping.find(entry_id_tag)
                            if entry_id_elem is not None and entry_id_elem.text:
                                mapping_data['entry_id'] = entry_id_elem.text.strip()
                            
                            # Extract Entry_Name if present
                            entry_name_elem = mapping.find(entry_name_tag)
                            if entry_name_elem is not None and entry_name_elem.text:
                                mapping_data['entry_name'] = entry_name_elem.text.strip()
                            
                            capec_data['taxonomy_mappings'].append(mapping_data)
                
                capec_mapping[capec_id] = capec_data
        
        logging.info(f"Loaded {len(capec_mapping)} CAPEC attack patterns from {capec_file}")
        
    except ET.ParseError as e:
        logging.error(f"Error parsing CAPEC XML file: {e}")
    except Exception as e:
        logging.error(f"Unexpected error loading CAPEC data: {e}")
    
    _capec_cache = capec_mapping
    return _capec_cache

def _get_capec_name(capec_id: str) -> str:
    """Gets the CAPEC attack pattern name for a given CAPEC ID.
    
    Args:
        capec_id: CAPEC ID in format "CAPEC-123" or just "123"
        
    Returns:
        The attack pattern name, or "Unknown" if not found
    """
    capec_data = _get_capec_data(capec_id)
    return capec_data.get('name', 'Unknown')

def _get_capec_data(capec_id: str) -> dict:
    """Gets complete CAPEC attack pattern data for a given CAPEC ID.
    
    Args:
        capec_id: CAPEC ID in format "CAPEC-123" or just "123"
        
    Returns:
        Dictionary with CAPEC data including name and taxonomy mappings,
        or empty dict if not found
    """
    capec_mapping = _load_capec_names()
    
    # Extract numeric part from CAPEC ID
    if capec_id.startswith('CAPEC-'):
        numeric_id = capec_id[6:]
    else:
        numeric_id = capec_id
    
    return capec_mapping.get(numeric_id, {})

async def _fetch_cwe_data(cwe_id: str) -> dict:
    """Fetches CWE data from the CWE API for a given CWE ID."""
    
    # Extract numeric part from CWE ID (e.g., "CWE-295" -> "295")
    if cwe_id.startswith('CWE-'):
        cwe_number = cwe_id[4:]
    else:
        cwe_number = cwe_id
    
    url = f"https://cwe-api.mitre.org/api/v1/cwe/weakness/{cwe_number}"
    
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.get(url)
            response.raise_for_status()
            cwe_data = response.json()
            
            if 'Weaknesses' in cwe_data and cwe_data['Weaknesses']:
                weakness = cwe_data['Weaknesses'][0]  # Take the first weakness
                
                # Extract CommonConsequences data
                consequences = {
                    'scopes': [],
                    'impacts': [],
                    'consequences_available': False
                }
                
                if 'CommonConsequences' in weakness and weakness['CommonConsequences']:
                    consequences['consequences_available'] = True
                    for consequence in weakness['CommonConsequences']:
                        if 'Scope' in consequence and isinstance(consequence['Scope'], list):
                            consequences['scopes'].extend(consequence['Scope'])
                        if 'Impact' in consequence and isinstance(consequence['Impact'], list):
                            consequences['impacts'].extend(consequence['Impact'])
                
                # Remove duplicates while preserving order
                consequences['scopes'] = list(dict.fromkeys(consequences['scopes']))
                consequences['impacts'] = list(dict.fromkeys(consequences['impacts']))
                
                # Extract RelatedAttackPatterns (CAPEC IDs)
                related_capec = {
                    'capec_ids': [],
                    'capec_available': False
                }
                
                if 'RelatedAttackPatterns' in weakness and weakness['RelatedAttackPatterns']:
                    related_capec['capec_available'] = True
                    capec_ids = []
                    for pattern_id in weakness['RelatedAttackPatterns']:
                        # Format as CAPEC-{ID}
                        if isinstance(pattern_id, str) and pattern_id.isdigit():
                            capec_ids.append(f"CAPEC-{pattern_id}")
                        elif isinstance(pattern_id, int):
                            capec_ids.append(f"CAPEC-{pattern_id}")
                    
                    related_capec['capec_ids'] = capec_ids
                
                return {
                    'cwe_id': cwe_id,
                    'name': weakness.get('Name', 'N/A'),
                    'description': weakness.get('Description', 'N/A'),
                    'consequences': consequences,
                    'related_capec': related_capec,
                    'error': None
                }
            else:
                return {
                    'cwe_id': cwe_id,
                    'error': f"No weakness data found for {cwe_id}"
                }
                
    except httpx.HTTPStatusError as e:
        return {
            'cwe_id': cwe_id,
            'error': f"HTTP error {e.response.status_code} for {cwe_id}"
        }
    except httpx.RequestError as e:
        return {
            'cwe_id': cwe_id,
            'error': f"Request error for {cwe_id}: {str(e)}"
        }
    except Exception as e:
        return {
            'cwe_id': cwe_id,
            'error': f"Unexpected error for {cwe_id}: {str(e)}"
        }


async def _fetch_cve_data(cve_id: str, api_key: str) -> dict:
    """Fetches raw CVE data from Vulners API and returns structured data without formatting."""

    cve_fields = [
        "published", "id", "title", "description", "cvelist", "metrics", "epss", "cwe",
        "references", "enchantments.exploitation", "enchantments.dependencies.references",
        "cnaAffected", "solutions", "workarounds"
    ]
    url = "https://vulners.com/api/v3/search/id"
    payload = {"id": cve_id, "fields": cve_fields}
    headers = {
        'Content-Type': 'application/json',
        'X-Api-Key': api_key
    }

    try:
        timeout = httpx.Timeout(60.0, connect=15.0)  # 60s total, 15s connect
        async with httpx.AsyncClient(timeout=timeout) as client:
            logging.debug(f"Making CVE API request for {cve_id} to {url}")
            response = await client.post(url, json=payload, headers=headers)
            logging.debug(f"CVE API response status: {response.status_code}")
            response.raise_for_status()
            response_data = response.json()
            logging.debug(f"CVE API response data keys: {list(response_data.keys()) if isinstance(response_data, dict) else 'Not a dict'}")

            if 'data' in response_data and 'documents' in response_data['data'] and cve_id in response_data['data']['documents']:
                cve_data_for_id = response_data['data']['documents'][cve_id]
                
                # Extract structured data
                cve_data = {
                    'core_info': {
                        'id': cve_data_for_id.get('id', 'N/A'),
                        'published': cve_data_for_id.get('published', 'N/A'),
                        'title': cve_data_for_id.get('title', 'N/A'),
                        'description': cve_data_for_id.get('description', 'N/A')
                    },
                    'cvss_metrics': [],
                    'ssvc_metrics': [],
                    'epss_score': None,
                    'cwe_classifications': [],
                    'exploitation_status': None,
                    'references': [],
                    'affected_products': [],
                    'cvelist': [],
                    'solutions': [],
                    'workarounds': [],
                    'raw_data': cve_data_for_id,
                    'error': None
                }

                # Process metrics field which includes CVSS from multiple sources and SSVC
                if 'metrics' in cve_data_for_id and isinstance(cve_data_for_id['metrics'], dict):
                    metrics = cve_data_for_id['metrics']
                    
                    for source_name, source_data in metrics.items():
                        if not isinstance(source_data, dict):
                            continue
                            
                        # Handle SSVC (from Vulnrichment/ADP)
                        if source_name == 'adp' and 'ssvc' in source_data:
                            ssvc_data = source_data['ssvc']
                            if isinstance(ssvc_data, dict):
                                ssvc_entry = {
                                    'role': ssvc_data.get('role', 'N/A'),
                                    'version': ssvc_data.get('version', 'N/A'),
                                    'options': []
                                }
                                if 'options' in ssvc_data and isinstance(ssvc_data['options'], list):
                                    for option in ssvc_data['options']:
                                        if isinstance(option, dict):
                                            ssvc_entry['options'].extend([f"{key}={value}" for key, value in option.items()])
                                cve_data['ssvc_metrics'].append(ssvc_entry)
                        
                        # Handle CVSS data (different versions)
                        for cvss_key, cvss_data in source_data.items():
                            if not isinstance(cvss_data, dict) or cvss_key == 'ssvc':
                                continue
                                
                            if cvss_key.startswith('cvss'):
                                cvss_entry = {
                                    'version': cvss_data.get('version', 'N/A'),
                                    'source': cvss_data.get('source', source_name),
                                    'base_score': cvss_data.get('baseScore', 'N/A'),
                                    'base_severity': cvss_data.get('baseSeverity', 'N/A'),
                                    'vector_string': cvss_data.get('vectorString', 'N/A'),
                                    'v4_fields': {}
                                }
                                
                                # Add additional CVSS v4.0 specific fields if present
                                if cvss_entry['version'] == "4.0":
                                    v4_fields = ['attackRequirements', 'safety', 'automatable', 'recovery', 'providerUrgency']
                                    for field in v4_fields:
                                        if field in cvss_data:
                                            cvss_entry['v4_fields'][field] = cvss_data[field]
                                
                                cve_data['cvss_metrics'].append(cvss_entry)

                # Process EPSS data
                if 'epss' in cve_data_for_id and isinstance(cve_data_for_id['epss'], list):
                    latest_epss_entry = None
                    latest_date = None
                    for epss_entry_item in cve_data_for_id['epss']:
                        if isinstance(epss_entry_item, dict) and 'date' in epss_entry_item and \
                           (latest_date is None or epss_entry_item['date'] > latest_date):
                            latest_epss_entry = epss_entry_item
                            latest_date = epss_entry_item['date']
                    
                    if latest_epss_entry:
                        cve_data['epss_score'] = {
                            'score': latest_epss_entry.get('epss', 'N/A'),
                            'percentile': latest_epss_entry.get('percentile', 'N/A'),
                            'date': latest_epss_entry.get('date', 'N/A')
                        }

                # Process CWE classifications
                if 'cwe' in cve_data_for_id and cve_data_for_id['cwe'] and isinstance(cve_data_for_id['cwe'], list):
                    cve_data['cwe_classifications'] = cve_data_for_id['cwe']

                # Process exploitation status
                if 'enchantments' in cve_data_for_id and \
                   isinstance(cve_data_for_id.get('enchantments'), dict) and \
                   'exploitation' in cve_data_for_id['enchantments'] and \
                   isinstance(cve_data_for_id['enchantments']['exploitation'], dict):
                    exploitation_info = cve_data_for_id['enchantments']['exploitation']
                    if 'wildExploited' in exploitation_info:
                        sources_list = []
                        if exploitation_info['wildExploited'] and \
                           'wildExploitedSources' in exploitation_info and \
                           isinstance(exploitation_info['wildExploitedSources'], list):
                            sources_list = [source['type'] for source in exploitation_info['wildExploitedSources'] 
                                       if isinstance(source, dict) and 'type' in source]
                        
                        cve_data['exploitation_status'] = {
                            'wild_exploited': exploitation_info['wildExploited'],
                            'sources': sources_list
                        }

                # Process references
                if 'references' in cve_data_for_id and isinstance(cve_data_for_id['references'], list):
                    cve_data['references'] = cve_data_for_id['references']

                # Process affected products
                if 'cnaAffected' in cve_data_for_id:
                    cve_data['affected_products'] = _process_cve_affected_products(cve_data_for_id['cnaAffected'])

                # Process CVE list
                cvelist = cve_data_for_id.get('cvelist', [])
                if isinstance(cvelist, list):
                    cve_data['cvelist'] = cvelist

                # Process solutions
                solutions = cve_data_for_id.get('solutions', [])
                if isinstance(solutions, list):
                    for solution in solutions:
                        if isinstance(solution, dict):
                            # Only use English if language is specified
                            lang = solution.get('lang', '')
                            if not lang or lang == 'en':
                                # Only use value key
                                value = solution.get('value', '').strip()
                                if value:
                                    cve_data['solutions'].append(value)

                # Process workarounds  
                workarounds = cve_data_for_id.get('workarounds', [])
                if isinstance(workarounds, list):
                    for workaround in workarounds:
                        if isinstance(workaround, dict):
                            # Only use English if language is specified
                            lang = workaround.get('lang', '')
                            if not lang or lang == 'en':
                                # Only use value key
                                value = workaround.get('value', '').strip()
                                if value:
                                    cve_data['workarounds'].append(value)

                return cve_data
            else:
                error_msg = f"CVE {cve_id} not found or invalid response structure"
                logging.error(f"CVE API response error: {error_msg}. Response: {response_data}")
                return {'error': error_msg, 'raw_data': response_data}

    except httpx.HTTPStatusError as e:
        # Clean up error messages for common API issues
        if e.response.status_code == 502:
            error_details = f"HTTP 502 - Vulners API temporarily unavailable (Bad Gateway). Try again in a few minutes."
        elif e.response.status_code == 503:
            error_details = f"HTTP 503 - Vulners API service temporarily unavailable. Try again later."
        elif e.response.status_code == 504:
            error_details = f"HTTP 504 - Vulners API gateway timeout. The request took too long to process."
        elif e.response.status_code == 429:
            error_details = f"HTTP 429 - Vulners API rate limit exceeded. Wait before making more requests."
        else:
            # For other HTTP errors, include limited response text
            response_text = e.response.text[:200] if e.response.text else "No response body"
            error_details = f"HTTP {e.response.status_code} - {response_text}"
        
        logging.error(f"CVE API HTTP error for {cve_id}: HTTP {e.response.status_code}")
        return {'error': error_details, 'raw_data': None}
    except (httpx.TimeoutException, httpx.ReadTimeout, httpx.WriteTimeout, httpx.PoolTimeout, httpx.ConnectTimeout) as e:
        timeout_type = type(e).__name__
        if timeout_type == "ReadTimeout":
            error_details = f"Vulners API read timeout - The server took too long to respond. This may indicate server overload."
        elif timeout_type == "ConnectTimeout":
            error_details = f"Vulners API connection timeout - Unable to establish connection within 15 seconds."
        elif timeout_type == "WriteTimeout":
            error_details = f"Vulners API write timeout - Request data could not be sent within the timeout period."
        else:
            error_details = f"Vulners API timeout ({timeout_type}) - Request exceeded 60 second limit."
        
        logging.error(f"CVE API timeout for {cve_id}: {timeout_type} - {str(e)}")
        return {'error': error_details, 'raw_data': None}
    except httpx.RequestError as e:
        error_details = f"Request failed - {type(e).__name__}: {e}"
        logging.error(f"CVE API request error for {cve_id}: {error_details}")
        return {'error': error_details, 'raw_data': None}
    except Exception as e:
        error_details = f"Unexpected error - {type(e).__name__}: {e}"
        logging.error(f"CVE API unexpected error for {cve_id}: {error_details}")
        return {'error': error_details, 'raw_data': None}

async def _fetch_related_documents_data(cve_data_json: dict, api_key: str) -> dict:
    """Fetches related documents data from Vulners API and returns structured data without formatting."""
    
    result = {
        'documents': [],
        'related_cves': [],
        'cve_source_tracking': {},  # Track which documents mention each CVE
        'error': None,
        'document_count': 0,
        'affected_os_by_document': {},
        'solutions': {}  # Will store source category -> set of unique solutions
    }

    combined_ids_from_all_idlists = []
    all_documents = {}
    cve_id_for_fallback = cve_data_json.get('id', '') if isinstance(cve_data_json, dict) else ''

    enchantments = cve_data_json.get('enchantments')
    if isinstance(enchantments, dict):
        dependencies = enchantments.get('dependencies')
        if isinstance(dependencies, dict):
            references_list = dependencies.get('references')
            if isinstance(references_list, list):
                if not references_list:
                    # Keep error note but do not return; we'll try Lucene fallback below
                    result['error'] = 'NO_DOCUMENTS'
                else:
                    for item in references_list:
                        if isinstance(item, dict):
                            id_list_from_item = item.get('idList')
                            if isinstance(id_list_from_item, list):
                                filtered_ids = [id_val for id_val in id_list_from_item 
                                              if not any(unwanted in str(id_val).lower() 
                                                        for unwanted in ['nvd', 'cvelist', 'vulnrichment'])]
                                combined_ids_from_all_idlists.extend(filtered_ids)
                                logging.debug(f"Added {len(filtered_ids)} IDs from {item.get('type', 'unknown')} references (total so far: {len(combined_ids_from_all_idlists)})")
            else:
                # Keep error note but do not return; we'll try Lucene fallback below
                result['error'] = 'NO_REFERENCES_LIST'
        else:
            # Keep error note but do not return; we'll try Lucene fallback below
            result['error'] = 'NO_DEPENDENCIES'
    else:
        # Keep error note but do not return; we'll try Lucene fallback below
        result['error'] = 'NO_ENCHANTMENTS'
            
    if not combined_ids_from_all_idlists:
        # Lucene fallback: search all documents mentioning this CVE in cvelist
        if isinstance(cve_id_for_fallback, str) and cve_id_for_fallback:
            try:
                logging.info(f"No idList references found; performing Lucene fallback for {cve_id_for_fallback}")
                url = "https://vulners.com/api/v3/search/lucene"
                related_doc_fields = [
                    "type", "published", "id", "title", "href", "bulletinFamily",
                    "cvelist", "viewCount", "affectedPackage", "naslFamily", "solution"
                ]
                payload = {
                    "query": f"cvelist:{cve_id_for_fallback}",
                    "skip": 0,
                    "size": 200,
                    "fields": related_doc_fields
                }
                headers = {
                    'Content-Type': 'application/json',
                    'X-Api-Key': api_key
                }
                timeout = httpx.Timeout(60.0, connect=15.0)
                async with httpx.AsyncClient(timeout=timeout) as client:
                    logging.debug(f"Making Lucene fallback request to {url} for {cve_id_for_fallback}")
                    response = await client.post(url, json=payload, headers=headers)
                    logging.debug(f"Lucene fallback response status: {response.status_code}")
                    response.raise_for_status()
                    data = response.json()
                    search_hits = []
                    if isinstance(data, dict) and 'data' in data and isinstance(data['data'], dict):
                        search_hits = data['data'].get('search', [])
                    for hit in search_hits:
                        source = hit.get('_source') if isinstance(hit, dict) else None
                        if isinstance(source, dict):
                            # Filter out internal/non-authoritative families consistent with ID filtering logic
                            bf = str(source.get('bulletinFamily', '')).lower()
                            if bf in ['nvd', 'cvelist', 'vulnrichment']:
                                continue
                            doc_id = source.get('id')
                            if isinstance(doc_id, str) and doc_id:
                                all_documents[doc_id] = source
                if not all_documents:
                    result['error'] = 'NO_RELEVANT_IDS'
                    return result
                logging.info(f"Lucene fallback found {len(all_documents)} documents for {cve_id_for_fallback}")
            except httpx.HTTPStatusError as e:
                logging.error(f"Lucene fallback HTTP error: HTTP {e.response.status_code}")
                result['error'] = f"LUCENE_HTTP_ERROR_{e.response.status_code}"
                return result
            except Exception as e:
                logging.error(f"Lucene fallback unexpected error: {str(e)}")
                result['error'] = f"LUCENE_UNEXPECTED_ERROR_{str(e)}"
                return result

    # Process IDs in chunks to avoid API limits (Vulners API has ~100 ID limit)
    chunk_size = 100
    
    logging.debug(f"Processing {len(combined_ids_from_all_idlists)} related document IDs in chunks of {chunk_size}")
    
    for i in range(0, len(combined_ids_from_all_idlists), chunk_size):
        chunk = combined_ids_from_all_idlists[i:i + chunk_size]
        logging.debug(f"Processing chunk {i//chunk_size + 1}/{(len(combined_ids_from_all_idlists) + chunk_size - 1)//chunk_size} with {len(chunk)} IDs")
        
        # API Call to Vulners ID endpoint for each chunk
        url = "https://vulners.com/api/v3/search/id"
        related_doc_fields = ["type", "published", "id", "title", "href", "bulletinFamily", "cvelist", "viewCount", "affectedPackage", "naslFamily", "solution"]
        payload = {
            "id": chunk,
            "fields": related_doc_fields
        }
        headers = {
            'Content-Type': 'application/json',
            'X-Api-Key': api_key
        }

        try:
            timeout = httpx.Timeout(60.0, connect=15.0)  # 60s total, 15s connect
            async with httpx.AsyncClient(timeout=timeout) as client:
                logging.debug(f"Making related documents API request to {url} for chunk {i//chunk_size + 1}")
                response = await client.post(url, json=payload, headers=headers)
                logging.debug(f"Related documents API response status: {response.status_code}")
                response.raise_for_status()
                response_data = response.json()
                logging.debug(f"Related documents API response data keys: {list(response_data.keys()) if isinstance(response_data, dict) else 'Not a dict'}")

                if 'data' in response_data and 'documents' in response_data['data']:
                    documents = response_data['data']['documents']
                    
                    if isinstance(documents, dict):
                        # Merge documents from this chunk into the overall collection
                        all_documents.update(documents)
                        logging.debug(f"Added {len(documents)} documents from chunk {i//chunk_size + 1}, total: {len(all_documents)}")
                
        except httpx.HTTPStatusError as e:
            logging.error(f"HTTP error for chunk {i//chunk_size + 1}: HTTP {e.response.status_code}")
            result['error'] = f"HTTP_ERROR_{e.response.status_code}"
            return result
        except httpx.RequestError as e:
            logging.error(f"Request error for chunk {i//chunk_size + 1}: {str(e)}")
            result['error'] = f"REQUEST_ERROR_{str(e)}"
            return result
        except json.JSONDecodeError:
            logging.error(f"JSON decode error for chunk {i//chunk_size + 1}")
            result['error'] = 'JSON_DECODE_ERROR'
            return result
        except KeyError as e:
            logging.error(f"Key error for chunk {i//chunk_size + 1}: {str(e)}")
            result['error'] = f"KEY_ERROR_{str(e)}"
            return result
        except Exception as e:
            logging.error(f"Unexpected error for chunk {i//chunk_size + 1}: {str(e)}")
            result['error'] = f"UNEXPECTED_ERROR_{str(e)}"
            return result

    # Process all collected documents
    if all_documents:
        doc_list = [doc for doc in all_documents.values() if isinstance(doc, dict)]
        doc_list.sort(key=lambda x: x.get('published', ''))
        
        # Log bulletin family distribution for debugging
        bulletin_families = {}
        for doc in doc_list:
            family = doc.get('bulletinFamily', 'unknown')
            doc_type = doc.get('type', 'unknown')
            cve_count = len(doc.get('cvelist', [])) if isinstance(doc.get('cvelist'), list) else 0
            # Use both fields to get complete picture
            family_key = f"{family}/{doc_type}"
            if family_key not in bulletin_families:
                bulletin_families[family_key] = {'count': 0, 'total_cves': 0, 'large_cve_lists': 0, 'exploit_large_lists': 0}
            bulletin_families[family_key]['count'] += 1
            bulletin_families[family_key]['total_cves'] += cve_count
            if cve_count > 10:
                bulletin_families[family_key]['large_cve_lists'] += 1
        
        logging.debug(f"Bulletin family distribution: {bulletin_families}")

        if not doc_list:
            result['error'] = 'NO_DETAILS_FOUND'
            return result
        else:
            # Use all collected documents; do not drop by CVE count to avoid excluding vendor/scanner advisories
            filtered_docs = doc_list
            docs_filtered = 0
            logging.info("Document filtering: disabled CVE-count filter; including all referenced documents")
            
            if not filtered_docs:
                result['error'] = 'NO_DETAILS_FOUND'
                return result
            
            result['document_count'] = len(filtered_docs)
            logging.info(f"Successfully processed {len(filtered_docs)} related documents from {len(all_documents)} total documents")
            
            for doc_content in filtered_docs:
                doc_entry = {
                    'id': doc_content.get('id', 'N/A'),
                    'type': doc_content.get('bulletinFamily', 'N/A'),
                    'title': doc_content.get('title', 'N/A'),
                    'link': doc_content.get('href', 'N/A'),
                    'published': doc_content.get('published', 'N/A'),
                    'view_count': doc_content.get('viewCount', 'N/A')
                }
                result['documents'].append(doc_entry)
                
                cvelist = doc_content.get('cvelist')
                if isinstance(cvelist, list):
                    doc_id = doc_content.get('id', 'unknown')
                    doc_type = doc_content.get('bulletinFamily', doc_content.get('type', 'unknown'))
                    
                    # Add CVEs to the main list and track their sources
                    for cve in cvelist:
                        if isinstance(cve, str):
                            cve_upper = cve.upper()
                            result['related_cves'].append(cve_upper)
                            
                            # Track which document mentioned this CVE
                            if cve_upper not in result['cve_source_tracking']:
                                result['cve_source_tracking'][cve_upper] = []
                            
                            result['cve_source_tracking'][cve_upper].append({
                                'doc_id': doc_id,
                                'doc_type': doc_type,
                                'view_count': doc_content.get('viewCount', 0)
                            })
                
                # Process affected packages - track OS/version and document references
                affected_packages = doc_content.get('affectedPackage')
                if isinstance(affected_packages, list):
                    doc_href = doc_content.get('href', 'N/A')
                    doc_id = doc_content.get('id', 'N/A')
                    doc_type = doc_content.get('type', 'unknown')
                    
                    # Track unique OS/version combinations in this document
                    os_versions_in_doc = set()
                    
                    for package in affected_packages:
                        if isinstance(package, dict):
                            os_name = package.get('OS', '')
                            os_version = package.get('OSVersion', '')
                            
                            if os_name and os_version:
                                os_key = f"{os_name} {os_version}"
                                os_versions_in_doc.add(os_key)
                    
                    # Add document reference for each OS/version found
                    for os_key in os_versions_in_doc:
                        if os_key not in result['affected_os_by_document']:
                            result['affected_os_by_document'][os_key] = []
                        
                        # Store document reference info with type for sorting
                        doc_ref = {
                            'id': doc_id,
                            'href': doc_href,
                            'type': doc_type
                        }
                        result['affected_os_by_document'][os_key].append(doc_ref)
                
                # Process external source solutions - extract category and solution pairs
                doc_type = doc_content.get('type', '').lower()
                if doc_type == 'nessus':
                    nessus_family = doc_content.get('naslFamily', '').strip()
                    solution = doc_content.get('solution', '').strip()
                    
                    if nessus_family and solution:
                        # Normalize the source category for consistent grouping
                        nessus_family = ' '.join(nessus_family.split())
                        solution = ' '.join(solution.split())
                        
                        if nessus_family not in result['solutions']:
                            result['solutions'][nessus_family] = set()
                        
                        # Add solution to the set (automatically deduplicates)
                        result['solutions'][nessus_family].add(solution)
    else:
        result['error'] = 'NO_DOCUMENT_DETAILS'

    # Apply intelligent CVE filtering based on frequency and evidence strength
    result['related_cves'] = _filter_cves_by_frequency(result['related_cves'], result['cve_source_tracking'])
    
    return result

def _filter_cves_by_frequency(related_cves: list, cve_source_tracking: dict) -> list[str]:
    """Applies intelligent CVE filtering based on frequency and evidence strength.
    
    This function implements sophisticated logic to filter out "fat finger" CVE mentions
    while preserving legitimate vulnerability connections. It considers:
    - Frequency of CVE mentions across documents
    - Quality of evidence (document type diversity, popularity)
    - Statistical distribution of evidence strength
    
    Args:
        related_cves: List of CVE IDs that may contain duplicates
        cve_source_tracking: Dictionary mapping CVE IDs to their source documents
        
    Returns:
        Filtered list of CVE IDs with low-confidence entries removed
    """
    if not related_cves:
        return []
    
    # Handle edge case: empty or invalid source tracking
    if not cve_source_tracking or not isinstance(cve_source_tracking, dict):
        logging.debug("CVE filtering: No source tracking data, falling back to simple deduplication")
        return sorted(list(set(cve.upper() for cve in related_cves if isinstance(cve, str))))
    
    # Count frequency of each CVE and assess evidence quality
    cve_frequency = {}
    cve_evidence_quality = {}
    
    for cve in related_cves:
        if isinstance(cve, str):
            cve_upper = cve.upper()
            cve_frequency[cve_upper] = cve_frequency.get(cve_upper, 0) + 1
    
    # Assess evidence quality for each CVE based on source tracking
    for cve_id, sources in cve_source_tracking.items():
        if isinstance(sources, list):
            # Count unique document types and total view counts
            doc_types = set()
            total_view_count = 0
            unique_docs = len(sources)
            
            for source in sources:
                if isinstance(source, dict):
                    doc_types.add(source.get('doc_type', 'unknown'))
                    view_count = source.get('view_count', 0)
                    if isinstance(view_count, (int, float)):
                        total_view_count += view_count
            
            # Quality score based on source diversity and popularity
            type_diversity_score = len(doc_types)
            popularity_score = total_view_count / 1000  # Normalize view counts
            
            cve_evidence_quality[cve_id] = {
                'mention_count': unique_docs,
                'type_diversity': type_diversity_score,
                'popularity': popularity_score,
                'quality_score': unique_docs + type_diversity_score * 0.5 + min(popularity_score, 2.0)
            }
    
    # Get total number of unique CVEs and total evidence count
    unique_cve_count = len(cve_frequency)
    total_evidence = sum(cve_frequency.values())
    
    logging.debug(f"CVE filtering: {unique_cve_count} unique CVEs, {total_evidence} total evidence points")
    
    # Apply intelligent filtering logic based on evidence strength and quality
    if total_evidence <= 2:
        # Very few total sightings - keep everything
        filtered_cves = list(cve_frequency.keys())
        logging.debug("CVE filtering: Keeping all CVEs (low total evidence)")
    elif unique_cve_count <= 3:
        # Small number of unique CVEs - keep everything
        filtered_cves = list(cve_frequency.keys())
        logging.debug("CVE filtering: Keeping all CVEs (few unique CVEs)")
    else:
        # Apply intelligent filtering for larger datasets using both frequency and quality
        filtered_cves = []
        
        # Calculate composite scores combining frequency and evidence quality
        cve_scores = {}
        max_frequency = max(cve_frequency.values())
        
        for cve_id, frequency in cve_frequency.items():
            # Base score from frequency
            frequency_score = frequency
            
            # Quality bonus from evidence assessment
            quality_info = cve_evidence_quality.get(cve_id, {})
            quality_score = quality_info.get('quality_score', 1.0)
            
            # Composite score: frequency + quality bonus
            composite_score = frequency_score + (quality_score * 0.3)
            cve_scores[cve_id] = {
                'frequency': frequency,
                'quality_score': quality_score,
                'composite_score': composite_score,
                'quality_info': quality_info
            }
        
        # Determine filtering threshold (with safety checks for empty data)
        if not cve_scores:
            logging.debug("CVE filtering: No valid CVE scores calculated")
            return sorted(list(cve_frequency.keys()))
            
        max_composite = max(score_data['composite_score'] for score_data in cve_scores.values())
        avg_composite = sum(score_data['composite_score'] for score_data in cve_scores.values()) / unique_cve_count
        
        # Dynamic threshold based on data distribution
        if max_frequency >= 3:
            # Strong evidence available - be more selective
            base_threshold = max(1.5, avg_composite * 0.6)
        else:
            # Weaker evidence - be more lenient
            base_threshold = max(1.0, avg_composite * 0.4)
        
        # Consider evidence spread - if there's a big gap between top and average, be more selective
        if max_composite > avg_composite * 2:
            threshold = max(base_threshold, avg_composite * 0.8)
        else:
            threshold = base_threshold
        
        # Filter CVEs based on composite score
        for cve_id, score_data in cve_scores.items():
            if score_data['composite_score'] >= threshold:
                filtered_cves.append(cve_id)
        
        # Safety net: ensure we don't filter too aggressively
        if len(filtered_cves) < 2 and unique_cve_count > 2:
            # Sort by composite score and take top performers
            sorted_cves = sorted(cve_scores.items(), key=lambda x: x[1]['composite_score'], reverse=True)
            top_count = max(2, unique_cve_count // 2)
            filtered_cves = [cve_id for cve_id, _ in sorted_cves[:top_count]]
        
        logging.debug(f"CVE filtering: Applied composite threshold {threshold:.2f}, "
                     f"kept {len(filtered_cves)}/{unique_cve_count} CVEs")
        
        # Log detailed filtering results with quality information
        if logging.getLogger().isEnabledFor(logging.DEBUG):
            for cve_id, score_data in sorted(cve_scores.items(), 
                                           key=lambda x: x[1]['composite_score'], reverse=True):
                status = "KEPT" if cve_id in filtered_cves else "FILTERED"
                qual_info = score_data['quality_info']
                logging.debug(f"  {cve_id}: freq={score_data['frequency']}, "
                             f"quality={score_data['quality_score']:.2f} "
                             f"(docs={qual_info.get('mention_count', 0)}, "
                             f"types={qual_info.get('type_diversity', 0)}), "
                             f"composite={score_data['composite_score']:.2f} - {status}")
    
    return sorted(filtered_cves)

def _clean_text_for_llm(text: str) -> str:
    """Cleans and normalizes text for optimal LLM readability.
    
    Handles various formatting issues while preserving meaningful structure:
    - Removes excessive whitespace and normalizes spacing
    - Handles awkward line breaks and wrapping
    - Fixes broken quote formatting patterns
    - Normalizes technical identifiers
    - Preserves paragraph structure where meaningful
    """
    if not isinstance(text, str) or not text.strip():
        return text
    
    # Step 1: Handle specific broken quote patterns first
    # Fix the pattern like 'text "     " text' which should be 'text that text'
    cleaned = re.sub(r'"[\s]+?"', ' that ', text)
    
    # Step 2: Normalize line endings and handle wrapped lines
    # Replace various line ending combinations with single spaces initially
    cleaned = re.sub(r'\r\n|\r|\n', ' ', cleaned)
    
    # Step 3: Handle excessive whitespace
    # Replace multiple spaces/tabs with single space
    cleaned = re.sub(r'[ \t]+', ' ', cleaned)
    
    # Step 4: Handle awkward spacing around punctuation
    # Fix spacing before punctuation
    cleaned = re.sub(r'\s+([,.;:!?])', r'\1', cleaned)
    # Ensure space after punctuation (but not in URLs or version numbers)
    cleaned = re.sub(r'([,.;:!?])(?=[A-Za-z])', r'\1 ', cleaned)
    
    # Step 5: Handle quoted text formatting issues
    # Normalize various quote types and fix spacing
    cleaned = re.sub(r'[""\u201c\u201d]+', '"', cleaned)
    cleaned = re.sub(r"[''\u2018\u2019]+", "'", cleaned)
    # Fix spacing around quotes - but avoid empty quotes
    cleaned = re.sub(r'\s*"([^"]+?)"\s*', r' "\1" ', cleaned)
    # Remove empty quotes that might be left over
    cleaned = re.sub(r'\s*""\s*', ' ', cleaned)
    
    # Step 6: Handle sentence structure
    # Ensure proper spacing after sentence endings
    cleaned = re.sub(r'\.(?=[A-Z])', '. ', cleaned)
    
    # Step 7: Handle common CVE/technical text patterns
    # Fix spacing around technical identifiers (CVE, CWE, etc.)
    cleaned = re.sub(r'\b(CVE|CWE|CAPEC|KB|MS|RHSA|DSA|USN|ALSA|ELSA|SUSE-SU)\s*-\s*(\d+)', r'\1-\2', cleaned)
    # Fix pattern like "CVE - 2025 - 53770" to "CVE-2025-53770"
    cleaned = re.sub(r'\b(CVE|CWE|CAPEC)\s*-\s*(\d{4})\s*-\s*(\d+)', r'\1-\2-\3', cleaned)
    
    # Step 8: Handle paragraph breaks for long text
    # For very long descriptions, try to preserve meaningful paragraph breaks
    if len(cleaned) > 500:
        # Look for patterns that suggest paragraph breaks
        # Sentences ending with periods followed by capital letters might indicate new paragraphs
        cleaned = re.sub(r'\.(\s+)([A-Z][a-z]+(?:\s+[a-z]+)*\s+(?:is|are|has|have|will|can|may|must|should|would|could)\b)', r'.\n\n\2', cleaned)
        # Handle Microsoft/Apple style advisory formatting
        cleaned = re.sub(r'\.(\s+)(Microsoft|Apple|Google|Adobe|Oracle|Red Hat|SUSE|Ubuntu|Debian)\s+(?:is\s+)?(?:aware|preparing|has\s+released)', r'.\n\n\2', cleaned)
    
    # Step 9: Final cleanup
    # Remove leading/trailing whitespace
    cleaned = cleaned.strip()
    # Ensure no double spaces remain
    cleaned = re.sub(r'  +', ' ', cleaned)
    
    return cleaned

def _process_cve_affected_products(cna_affected_data) -> list[str]:
    """Processes cnaAffected data and returns a list of affected product descriptions.
    
    Combines vendor and product names intelligently - if vendor name is a substring 
    of the product name, only the product name is used. Includes platform information
    when available for enhanced vulnerability scope clarity. Ensures all descriptions are unique.
    """
    if not isinstance(cna_affected_data, list):
        return []
    
    affected_products = set()
    
    for item in cna_affected_data:
        if not isinstance(item, dict):
            continue
            
        vendor = item.get('vendor', '').strip()
        product = item.get('product', '').strip()
        platforms = item.get('platforms', [])
        
        if not product:
            continue
        
        # Normalize whitespace (replace multiple spaces with single space)
        vendor = ' '.join(vendor.split())
        product = ' '.join(product.split())
            
        # Smart vendor handling: check if vendor info is already represented in product
        if not vendor:
            base_product = product
        else:
            # Multiple checks for vendor redundancy
            vendor_lower = vendor.lower()
            product_lower = product.lower()
            
            # Check 1: Exact vendor is substring of product
            if vendor_lower in product_lower:
                base_product = product
            # Check 2: Check if main vendor words are already in product
            else:
                vendor_words = [word.lower() for word in vendor.split() if len(word) > 2]
                product_words = [word.lower() for word in product.split() if len(word) > 2]
                
                # If any significant vendor word is found in product, consider it redundant
                vendor_represented = False
                for vendor_word in vendor_words:
                    if any(vendor_word in product_word or product_word in vendor_word for product_word in product_words):
                        vendor_represented = True
                        break
                
                if vendor_represented:
                    base_product = product
                else:
                    # Combine vendor and product
                    base_product = f"{vendor} {product}"
        
        # Additional normalization
        base_product = ' '.join(base_product.split())  # Normalize whitespace again
        
        # Add platform information if available
        if isinstance(platforms, list) and platforms:
            # Clean, deduplicate, and format platforms while preserving order
            seen_platforms = set()
            clean_platforms = []
            for platform in platforms:
                if isinstance(platform, str) and platform.strip():
                    clean_platform = platform.strip()
                    # Deduplicate case-insensitively but preserve original case
                    if clean_platform.lower() not in seen_platforms:
                        seen_platforms.add(clean_platform.lower())
                        clean_platforms.append(clean_platform)
            
            if clean_platforms:
                platforms_str = ', '.join(clean_platforms)
                final_product = f"{base_product} for {platforms_str}"
            else:
                final_product = base_product
        else:
            final_product = base_product
        
        affected_products.add(final_product)
    
    # Convert to list, sort, and ensure final uniqueness
    unique_products = sorted(list(affected_products))
    
    # Final pass to remove any case-insensitive duplicates while preserving original case
    final_unique = []
    seen_lower = set()
    
    for product in unique_products:
        product_lower = product.lower()
        if product_lower not in seen_lower:
            seen_lower.add(product_lower)
            final_unique.append(product)
    
    return final_unique

async def _fetch_bulletin_data(bulletin_id: str, api_key: str) -> dict:
    """Fetches raw bulletin data from Vulners API for any bulletin ID and returns structured data."""
    
    bulletin_fields = [
        "published", "id", "title", "description", "cvelist",
        "references", "bulletinFamily", "type", "href"
    ]
    url = "https://vulners.com/api/v3/search/id"
    payload = {"id": bulletin_id, "fields": bulletin_fields}
    headers = {
        'Content-Type': 'application/json',
        'X-Api-Key': api_key
    }

    try:
        timeout = httpx.Timeout(60.0, connect=15.0)  # 60s total, 15s connect
        async with httpx.AsyncClient(timeout=timeout) as client:
            logging.debug(f"Making bulletin API request for {bulletin_id} to {url}")
            response = await client.post(url, json=payload, headers=headers)
            logging.debug(f"Bulletin API response status: {response.status_code}")
            response.raise_for_status()
            response_data = response.json()
            logging.debug(f"Bulletin API response data keys: {list(response_data.keys()) if isinstance(response_data, dict) else 'Not a dict'}")

            if 'data' in response_data and 'documents' in response_data['data'] and bulletin_id in response_data['data']['documents']:
                bulletin_data_for_id = response_data['data']['documents'][bulletin_id]
                
                # Extract structured data - only essential fields
                bulletin_data = {
                    'core_info': {
                        'id': bulletin_data_for_id.get('id', 'N/A'),
                        'published': bulletin_data_for_id.get('published', 'N/A'),
                        'title': bulletin_data_for_id.get('title', 'N/A'),
                        'description': bulletin_data_for_id.get('description', 'N/A'),
                        'type': bulletin_data_for_id.get('bulletinFamily', bulletin_data_for_id.get('type', 'N/A')),
                        'href': bulletin_data_for_id.get('href', 'N/A')
                    },
                    'references': [],
                    'cvelist': [],
                    'raw_data': bulletin_data_for_id,
                    'error': None
                }

                # Process references and extract CVE IDs from them
                extracted_cves = set()
                if 'references' in bulletin_data_for_id and isinstance(bulletin_data_for_id['references'], list):
                    bulletin_data['references'] = bulletin_data_for_id['references']
                    
                    # Extract CVE IDs from all references
                    for ref in bulletin_data_for_id['references']:
                        if isinstance(ref, str):
                            # Extract CVE IDs from reference URL/text
                            cve_matches = re.findall(r'CVE-\d{4}-\d{4,}', ref, re.IGNORECASE)
                            extracted_cves.update([cve.upper() for cve in cve_matches])
                        elif isinstance(ref, dict):
                            # Check various fields in reference dict for CVE IDs
                            for key, value in ref.items():
                                if isinstance(value, str):
                                    cve_matches = re.findall(r'CVE-\d{4}-\d{4,}', value, re.IGNORECASE)
                                    extracted_cves.update([cve.upper() for cve in cve_matches])

                # Also extract CVE IDs from title and description
                for field_name in ['title', 'description']:
                    field_value = bulletin_data_for_id.get(field_name, '')
                    if isinstance(field_value, str):
                        cve_matches = re.findall(r'CVE-\d{4}-\d{4,}', field_value, re.IGNORECASE)
                        extracted_cves.update([cve.upper() for cve in cve_matches])

                # Process existing CVE list and combine with extracted CVEs
                existing_cvelist = bulletin_data_for_id.get('cvelist', [])
                combined_cves = set()
                
                # Add existing CVEs from bulletin
                if isinstance(existing_cvelist, list):
                    combined_cves.update([cve.upper() for cve in existing_cvelist if isinstance(cve, str)])
                
                # Add CVEs extracted from references, title, and description
                combined_cves.update(extracted_cves)
                
                # Convert back to sorted list
                bulletin_data['cvelist'] = sorted(list(combined_cves))
                
                # Log CVE extraction results if debug mode is enabled
                if extracted_cves:
                    logging.debug(f"Extracted CVE IDs from bulletin {bulletin_id} references/text: {sorted(list(extracted_cves))}")
                if len(combined_cves) > len(existing_cvelist):
                    logging.debug(f"Total CVEs for bulletin {bulletin_id}: {len(combined_cves)} (original: {len(existing_cvelist)}, extracted: {len(extracted_cves)})")

                return bulletin_data
            else:
                error_msg = f"Bulletin {bulletin_id} not found in Vulners database"
                logging.error(f"Bulletin API response error: {error_msg}. Response: {response_data}")
                return {'error': error_msg, 'raw_data': response_data}

    except httpx.HTTPStatusError as e:
        # Clean up error messages for common API issues
        if e.response.status_code == 502:
            error_details = f"HTTP 502 - Vulners API temporarily unavailable (Bad Gateway). Try again in a few minutes."
        elif e.response.status_code == 503:
            error_details = f"HTTP 503 - Vulners API service temporarily unavailable. Try again later."
        elif e.response.status_code == 504:
            error_details = f"HTTP 504 - Vulners API gateway timeout. The request took too long to process."
        elif e.response.status_code == 429:
            error_details = f"HTTP 429 - Vulners API rate limit exceeded. Wait before making more requests."
        else:
            # For other HTTP errors, include limited response text
            response_text = e.response.text[:200] if e.response.text else "No response body"
            error_details = f"HTTP {e.response.status_code} - {response_text}"
        
        logging.error(f"Bulletin API HTTP error for {bulletin_id}: HTTP {e.response.status_code}")
        return {'error': error_details, 'raw_data': None}
    except (httpx.TimeoutException, httpx.ReadTimeout, httpx.WriteTimeout, httpx.PoolTimeout, httpx.ConnectTimeout) as e:
        timeout_type = type(e).__name__
        if timeout_type == "ReadTimeout":
            error_details = f"Vulners API read timeout - The server took too long to respond. This may indicate server overload."
        elif timeout_type == "ConnectTimeout":
            error_details = f"Vulners API connection timeout - Unable to establish connection within 15 seconds."
        elif timeout_type == "WriteTimeout":
            error_details = f"Vulners API write timeout - Request data could not be sent within the timeout period."
        else:
            error_details = f"Vulners API timeout ({timeout_type}) - Request exceeded 60 second limit."
        
        logging.error(f"Bulletin API timeout for {bulletin_id}: {timeout_type} - {str(e)}")
        return {'error': error_details, 'raw_data': None}
    except httpx.RequestError as e:
        error_details = f"Request failed - {type(e).__name__}: {e}"
        logging.error(f"Bulletin API request error for {bulletin_id}: {error_details}")
        return {'error': error_details, 'raw_data': None}
    except Exception as e:
        error_details = f"Unexpected error - {type(e).__name__}: {e}"
        logging.error(f"Bulletin API unexpected error for {bulletin_id}: {error_details}")
        return {'error': error_details, 'raw_data': None}


async def _fetch_circl_document_data(cve_id: str, api_key: str) -> dict:
    """Fetches CIRCL document data for a given CVE ID and extracts Shadowserver information."""
    
    # Construct CIRCL document ID
    circl_doc_id = f"CIRCL:{cve_id}"
    
    url = "https://vulners.com/api/v3/search/id"
    payload = {"id": circl_doc_id, "fields": ["items", "id", "title"]}
    headers = {
        'Content-Type': 'application/json',
        'X-Api-Key': api_key
    }

    try:
        timeout = httpx.Timeout(60.0, connect=15.0)
        async with httpx.AsyncClient(timeout=timeout) as client:
            logging.debug(f"Making CIRCL document API request for {circl_doc_id}")
            response = await client.post(url, json=payload, headers=headers)
            logging.debug(f"CIRCL document API response status: {response.status_code}")
            response.raise_for_status()
            response_data = response.json()
            
            if 'data' in response_data and 'documents' in response_data['data'] and circl_doc_id in response_data['data']['documents']:
                circl_data = response_data['data']['documents'][circl_doc_id]
                
                # Extract Shadowserver items
                shadowserver_items = []
                if 'items' in circl_data and isinstance(circl_data['items'], list):
                    for item in circl_data['items']:
                        if isinstance(item, dict):
                            source = item.get('source', '')
                            if source.startswith('The Shadowserver'):
                                # Extract creation timestamp and source
                                creation_timestamp = item.get('creation_timestamp', '')
                                shadowserver_items.append({
                                    'source': source,
                                    'creation_timestamp': creation_timestamp
                                })
                
                # Sort by creation timestamp (oldest to newest)
                shadowserver_items.sort(key=lambda x: x.get('creation_timestamp', ''))
                
                return {
                    'shadowserver_items': shadowserver_items,
                    'error': None
                }
            else:
                logging.debug(f"CIRCL document {circl_doc_id} not found")
                return {
                    'shadowserver_items': [],
                    'error': None
                }

    except httpx.HTTPStatusError as e:
        logging.error(f"HTTP error fetching CIRCL document {circl_doc_id}: HTTP {e.response.status_code}")
        return {
            'shadowserver_items': [],
            'error': f"HTTP_ERROR_{e.response.status_code}"
        }
    except Exception as e:
        logging.error(f"Error fetching CIRCL document {circl_doc_id}: {str(e)}")
        return {
            'shadowserver_items': [],
            'error': f"FETCH_ERROR_{str(e)}"
        }




def _validate_bulletin_id(bulletin_id: str) -> tuple[bool, str]:
    """Validates bulletin ID format and returns (is_valid, error_message)."""
    if not bulletin_id or not isinstance(bulletin_id, str):
        return False, "Bulletin ID must be a non-empty string"
    
    # Only reject obvious non-bulletin-IDs: URLs and CVE IDs
    # Keep validation minimal since bulletin IDs come in many formats from different vendors
    
    # Reject URLs - these are clearly not bulletin IDs
    if bulletin_id.startswith(('http://', 'https://')):
        return False, f"Invalid bulletin ID: {bulletin_id}. URLs are not bulletin IDs. Use only bulletin identifiers that appear in CVE search results [RELATED_DOCUMENTS] section."
    
    # Reject CVE IDs - these are vulnerability IDs, not bulletin IDs
    if bulletin_id.startswith('CVE-'):
        return False, f"Invalid bulletin ID: {bulletin_id}. CVE IDs are not bulletin IDs. Use only bulletin identifiers that appear in CVE search results [RELATED_DOCUMENTS] section."
    
    # Accept everything else - bulletin IDs come in many formats from different vendors
    # The real validation is that they must come from CVE search results
    return True, ""



@mcp.tool(
    name="vulners_cve_info", 
    description="Retrieve comprehensive vulnerability intelligence for any CVE ID from the Vulners database, providing multi-layered threat analysis data and connected document discovery. Output is optimized for CrewAI consumption with structured JSON format.",
    structured_output=True
)
async def vulners_cve_info(cve_id: str) -> CveInfoOutput:
    """Retrieve comprehensive vulnerability intelligence using clean separation of data fetching and formatting."""

    logging.info(f"Starting CVE analysis for: {cve_id}")
    logging.debug(f"Fetching detailed information from Vulners API for: {cve_id}")

    # Validate input using Pydantic
    try:
        input_data = CveInfoInput(cve_id=cve_id)
        cve_id = input_data.cve_id  # Use validated and normalized CVE ID
    except ValueError as e:
        logging.error(f"CVE input validation failed: {e}")
        return CveInfoOutput(
            success=False,
            error=str(e),
            cve_id=cve_id
        )

    api_key = os.getenv("VULNERS_API_KEY")

    if not api_key:
        error_msg = "VULNERS_API_KEY not configured"
        logging.error(f"CVE {cve_id} failed: {error_msg}")
        return CveInfoOutput(
            success=False,
            error=f"{error_msg}. Please set VULNERS_API_KEY environment variable.",
            cve_id=cve_id
        )

    # Step 1: Fetch CVE data
    logging.debug(f"Step 1: Fetching CVE data for {cve_id}")
    cve_data = await _fetch_cve_data(cve_id, api_key)
    
    if cve_data.get('error'):
        error_msg = cve_data['error']
        logging.error(f"CVE {cve_id} data fetch failed: {error_msg}")
        return CveInfoOutput(
            success=False,
            error=error_msg,
            cve_id=cve_id
        )
    
    logging.info(f"CVE {cve_id} data fetch successful")

    # Step 2: Fetch related documents data
    related_docs_data = {'error': None, 'documents': [], 'related_cves': [], 'cve_titles': {}}
    if cve_data.get('raw_data'):
        related_docs_data = await _fetch_related_documents_data(cve_data['raw_data'], api_key)

    # Step 3: Fetch CWE consequences data
    cwe_consequences_data = []
    if cve_data.get('cwe_classifications'):
        logging.debug(f"Fetching CWE data for classifications: {cve_data['cwe_classifications']}")
        for cwe_id in cve_data['cwe_classifications']:
            cwe_data = await _fetch_cwe_data(cwe_id)
            cwe_consequences_data.append(cwe_data)
            logging.debug(f"CWE data for {cwe_id}: {cwe_data}")
    
    # Add CWE consequences data to cve_data for formatting
    if cwe_consequences_data:
        cve_data['cwe_consequences'] = cwe_consequences_data

    # Step 4: Fetch CIRCL document data for Shadowserver information
    logging.debug(f"Step 4: Fetching CIRCL document data for {cve_id}")
    circl_data = await _fetch_circl_document_data(cve_id, api_key)
    if circl_data.get('shadowserver_items'):
        cve_data['shadowserver_items'] = circl_data['shadowserver_items']
        logging.debug(f"Found {len(circl_data['shadowserver_items'])} Shadowserver items for {cve_id}")

    # Step 5: Combine all CVE IDs
    all_related_cves = set(cve_data.get('cvelist', []))
    all_related_cves.update(related_docs_data.get('related_cves', []))
    all_related_cves = list(all_related_cves)

    # Step 6: Format output as JSON for CrewAI consumption
    json_output = _format_cve_json_output(cve_data, related_docs_data, all_related_cves)
    
    logging.debug(f"json_output type: {type(json_output)}, value: {json_output}")

    # Step 7: Save debug output if debug mode is enabled
    _save_debug_output(cve_id, json.dumps(json_output, indent=2))

    # Step 8: Convert to Pydantic model for validation
    return _safe_pydantic_conversion(CveInfoOutput, json_output, "CVE output validation failed", cve_id=cve_id)

@mcp.tool(
    name="vulners_bulletin_info", 
    description="Retrieve essential bulletin information for any security bulletin ID (GHSA, RHSA, NASL, advisories, etc.) from the Vulners database. Output is optimized for CrewAI consumption with structured JSON format.",
    structured_output=True
)
async def vulners_bulletin_info(bulletin_id: str) -> BulletinInfoOutput:
    """Retrieve comprehensive vulnerability intelligence for any security bulletin ID from the Vulners database."""

    logging.info(f"Starting bulletin analysis for: {bulletin_id}")
    logging.debug(f"Fetching detailed information from Vulners API for bulletin: {bulletin_id}")

    # Validate input using Pydantic
    try:
        input_data = BulletinInfoInput(bulletin_id=bulletin_id)
        bulletin_id = input_data.bulletin_id
    except ValueError as e:
        logging.error(f"Bulletin input validation failed: {e}")
        return BulletinInfoOutput(
            success=False,
            error=str(e),
            bulletin_id=bulletin_id
        )

    api_key = os.getenv("VULNERS_API_KEY")

    if not api_key:
        logging.warning("VULNERS_API_KEY not found. Please set it.")
        return BulletinInfoOutput(
            success=False,
            error="VULNERS_API_KEY not configured.",
            bulletin_id=bulletin_id
        )
    
    # Validate bulletin ID format
    is_valid, error_msg = _validate_bulletin_id(bulletin_id)
    if not is_valid:
        logging.error(f"Bulletin ID validation failed: {error_msg}")
        return BulletinInfoOutput(
            success=False,
            error=error_msg,
            bulletin_id=bulletin_id
        )

    # Fetch bulletin data
    bulletin_data = await _fetch_bulletin_data(bulletin_id, api_key)
    
    if bulletin_data.get('error'):
        return BulletinInfoOutput(
            success=False,
            error=bulletin_data['error'],
            bulletin_id=bulletin_id
        )

    # Format output as JSON for CrewAI consumption
    json_output = _format_bulletin_json_output(bulletin_data)

    # Save debug output if debug mode is enabled
    _save_debug_output(bulletin_id, json.dumps(json_output, indent=2))

    # Convert to Pydantic model for validation
    return _safe_pydantic_conversion(BulletinInfoOutput, json_output, "Bulletin output validation failed", bulletin_id=bulletin_id)

def _format_cve_json_output(cve_data: dict, related_docs_data: dict, all_related_cves: list[str]) -> dict:
    """Formats structured CVE data into JSON output optimized for CrewAI consumption.
    
    Returns a JSON object with all available data, omitting fields that don't have data.
    """
    
    logging.debug(f"_format_cve_json_output called with cve_data keys: {list(cve_data.keys()) if cve_data else 'None'}")
    
    # Handle None or empty cve_data
    if not cve_data:
        logging.error("_format_cve_json_output received None or empty cve_data")
        return {
            "success": False,
            "error": "No CVE data received from API",
            "cve_id": ""
        }
    
    if cve_data.get('error'):
        logging.debug(f"Returning error response for CVE: {cve_data.get('core_info', {}).get('id', '')}")
        return {
            "success": False,
            "error": cve_data['error'],
            "cve_id": cve_data.get('core_info', {}).get('id', '')
        }
    
    # Start with core info
    core_info = cve_data.get('core_info', {})
    if not core_info:
        logging.error("No core_info found in cve_data")
        return {
            "success": False,
            "error": "No core information found in CVE data",
            "cve_id": ""
        }
    
    result = {
        "success": True,
        "cve_id": core_info.get('id', ''),
        "core_info": {
            "id": core_info.get('id', ''),
            "published": core_info.get('published', ''),
            "description": _clean_text_for_llm(core_info.get('description', ''))
        }
    }
    
    # Add CVSS metrics if available
    if cve_data.get('cvss_metrics'):
        result["cvss_metrics"] = []
        for cvss in cve_data['cvss_metrics']:
            cvss_entry = {
                "version": cvss['version'],
                "source": cvss['source'].upper() if cvss['source'] in ['nvd', 'cna'] else cvss['source'],
                "base_score": cvss['base_score'],
                "base_severity": cvss['base_severity'],
                "vector_string": cvss['vector_string']
            }
            if cvss.get('v4_fields'):
                cvss_entry["v4_fields"] = cvss['v4_fields']
            result["cvss_metrics"].append(cvss_entry)
    
    # Add SSVC metrics if available
    if cve_data.get('ssvc_metrics'):
        result["ssvc_metrics"] = []
        for ssvc in cve_data['ssvc_metrics']:
            ssvc_entry = {
                "role": ssvc['role'],
                "version": ssvc['version']
            }
            if ssvc.get('options'):
                ssvc_entry["options"] = ssvc['options']
            result["ssvc_metrics"].append(ssvc_entry)
    
    # Add EPSS score if available
    if cve_data.get('epss_score'):
        result["epss_score"] = {
            "score": cve_data['epss_score']['score'],
            "percentile": cve_data['epss_score']['percentile'],
            "date": cve_data['epss_score']['date']
        }
    
    # Add CWE classifications if available
    if cve_data.get('cwe_classifications'):
        result["cwe_classifications"] = cve_data['cwe_classifications']
    
    # Add CWE consequences and CAPEC data if available
    if cve_data.get('cwe_consequences'):
        result["cwe_consequences"] = []
        for cwe_info in cve_data['cwe_consequences']:
            if cwe_info.get('error'):
                continue
            
            cwe_entry = {
                "cwe_id": cwe_info['cwe_id'],
                "name": cwe_info.get('name', 'N/A')
            }
            
            # Add consequences if available
            consequences = cwe_info.get('consequences', {})
            if consequences.get('consequences_available') and (consequences.get('scopes') or consequences.get('impacts')):
                cwe_entry["consequences"] = {
                    "scopes": consequences.get('scopes', []),
                    "impacts": consequences.get('impacts', [])
                }
            
            # Add CAPEC information if available
            related_capec = cwe_info.get('related_capec', {})
            if related_capec.get('capec_available') and related_capec.get('capec_ids'):
                capec_data_list = []
                for capec_id in related_capec['capec_ids']:
                    capec_data = _get_capec_data(capec_id)
                    capec_entry = {
                        "id": capec_id,
                        "name": capec_data.get('name', 'Unknown'),
                        "taxonomy_mappings": capec_data.get('taxonomy_mappings', [])
                    }
                    capec_data_list.append(capec_entry)
                
                cwe_entry["related_capec"] = {
                    "capec_ids": related_capec['capec_ids'],
                    "capec_data": capec_data_list
                }
            
            # Only include if it has meaningful data
            if len(cwe_entry) > 2:  # More than just cwe_id and name
                result["cwe_consequences"].append(cwe_entry)
    
    # Add exploitation status if available
    if cve_data.get('exploitation_status'):
        exploit = cve_data['exploitation_status']
        result["exploitation_status"] = {
            "wild_exploited": exploit['wild_exploited'],
            "sources": exploit.get('sources', [])
        }
        
        # Add Shadowserver items if available
        if cve_data.get('shadowserver_items'):
            result["exploitation_status"]["shadowserver_items"] = []
            for item in cve_data['shadowserver_items']:
                result["exploitation_status"]["shadowserver_items"].append({
                    "source": item['source']
                })
    
    # Add references if available
    if cve_data.get('references'):
        result["references"] = cve_data['references']
    
    # Add affected products if available
    affected_products_list = []
    
    # Add products from CVE data
    if cve_data.get('affected_products'):
        affected_products_list.extend(cve_data['affected_products'])
    
    # Add OS/version entries from related documents
    if related_docs_data.get('affected_os_by_document'):
        normalized_os_to_data = {}
        
        # Group by normalized OS names and collect all hrefs and types
        for os_key, doc_refs in related_docs_data['affected_os_by_document'].items():
            if doc_refs:
                links = [doc_ref['href'] for doc_ref in doc_refs if doc_ref['href'] != 'N/A']
                types = [doc_ref.get('type', 'unknown') for doc_ref in doc_refs]
                
                if links:
                    normalized_os = os_key.lower()
                    
                    if normalized_os not in normalized_os_to_data:
                        normalized_os_to_data[normalized_os] = {
                            'original_names': [],
                            'all_hrefs': set(),
                            'document_types': set()
                        }
                    
                    normalized_os_to_data[normalized_os]['original_names'].append(os_key)
                    normalized_os_to_data[normalized_os]['all_hrefs'].update(links)
                    normalized_os_to_data[normalized_os]['document_types'].update(types)
                else:
                    affected_products_list.append(os_key)
        
        # Create entries with document type info
        for normalized_os, data in normalized_os_to_data.items():
            original_names = data['original_names']
            all_hrefs = data['all_hrefs']
            
            if original_names and all_hrefs:
                # Prefer capitalized version
                preferred_name = None
                for name in original_names:
                    if name and name[0].isupper():
                        preferred_name = name
                        break
                
                if not preferred_name:
                    preferred_name = original_names[0]
                
                href_str = ' | '.join(sorted(all_hrefs))
                affected_products_list.append(f"{preferred_name} (refs: {href_str})")
    
    if affected_products_list:
        result["affected_products"] = affected_products_list
    
    # Add related CVEs if available
    if all_related_cves:
        result["related_cves"] = sorted(all_related_cves)
    
    # Add solutions if available
    all_solutions = []
    
    # Add CVE solutions
    if cve_data.get('solutions'):
        for solution in cve_data['solutions']:
            cleaned_solution = _clean_text_for_llm(solution)
            all_solutions.append(cleaned_solution)
    
    # Add external source solutions
    if related_docs_data.get('solutions'):
        for source_category in sorted(related_docs_data['solutions'].keys()):
            unique_solutions = related_docs_data['solutions'][source_category]
            if unique_solutions:
                sorted_solutions = sorted(list(unique_solutions))
                for solution in sorted_solutions:
                    cleaned_solution = _clean_text_for_llm(solution)
                    prefixed_solution = f"{source_category}: {cleaned_solution}"
                    all_solutions.append(prefixed_solution)
    
    if all_solutions:
        result["solutions"] = all_solutions
    
    # Add workarounds if available
    if cve_data.get('workarounds'):
        result["workarounds"] = [_clean_text_for_llm(w) for w in cve_data['workarounds']]
    
    # Add related documents if available
    if related_docs_data.get('documents'):
        result["related_documents"] = []
        for doc in related_docs_data['documents']:
            result["related_documents"].append({
                "id": doc['id'],
                "type": doc['type'],
                "title": _clean_text_for_llm(doc['title']),
                "published": doc['published'],
                "view_count": doc['view_count'],
                "link": doc['link']
            })
    
    logging.debug(f"_format_cve_json_output returning result with keys: {list(result.keys())}")
    return result

def _format_bulletin_json_output(bulletin_data: dict) -> dict:
    """Formats structured bulletin data into JSON output optimized for CrewAI consumption.
    
    Returns a JSON object with all available data, omitting fields that don't have data.
    """
    
    if bulletin_data.get('error'):
        return {
            "success": False,
            "error": bulletin_data['error'],
            "bulletin_id": bulletin_data.get('core_info', {}).get('id', '')
        }
    
    # Start with core info
    result = {
        "success": True,
        "bulletin_id": bulletin_data['core_info']['id'],
        "core_info": {
            "id": bulletin_data['core_info']['id'],
            "type": bulletin_data['core_info']['type'],
            "published": bulletin_data['core_info']['published'],
            "description": _clean_text_for_llm(bulletin_data['core_info']['description'])
        }
    }
    
    # Add title if available
    if bulletin_data['core_info'].get('title') and bulletin_data['core_info']['title'] != 'N/A':
        result["core_info"]["title"] = _clean_text_for_llm(bulletin_data['core_info']['title'])
    
    # Add href if available
    if bulletin_data['core_info'].get('href') and bulletin_data['core_info']['href'] != 'N/A':
        result["core_info"]["href"] = bulletin_data['core_info']['href']
    
    # Add references if available
    if bulletin_data.get('references'):
        result["references"] = []
        for ref in bulletin_data['references']:
            if isinstance(ref, str):
                result["references"].append(ref)
            elif isinstance(ref, dict) and ref.get('url'):
                result["references"].append(ref['url'])
    
    # Add related CVEs if available
    if bulletin_data.get('cvelist'):
        result["related_cves"] = bulletin_data['cvelist']
    
    return result

if __name__ == "__main__":
    mcp.run()
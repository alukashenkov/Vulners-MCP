import asyncio
import json
import logging
import os
# import aiohttp # No longer needed
import httpx # Added for async HTTP requests

# cve_fields defines the specific fields to retrieve.
# You can customize this list as needed.

def _process_cve_json(cve_info_json: dict) -> str:
    """Processes the CVE JSON data and returns a formatted string."""
    cve_info = "\nCORE CVE INFO:\n"

    # Process CVE ID, Published, and Description
    cve_info += f"CVE ID: {cve_info_json.get('id', 'N/A')}\n"
    cve_info += f"Published: {cve_info_json.get('published', 'N/A')}\n"
    cve_info += f"Description: {cve_info_json.get('description', 'N/A')}\n"

    # Process CVSS
    if 'cvss' in cve_info_json and isinstance(cve_info_json['cvss'], dict):
        cvss_data = cve_info_json['cvss']
        score = cvss_data.get('score', 'N/A')
        severity = cvss_data.get('severity', 'N/A')
        vector = cvss_data.get('vector', 'N/A')
        version = cvss_data.get('version', 'N/A')
        cve_info += f"CVSS v{version}: {score} ({severity}) - Vector: {vector}\n"

    # Process EPSS
    if 'epss' in cve_info_json and isinstance(cve_info_json['epss'], list):
        latest_epss_entry = None
        latest_date = None
        for epss_entry_item in cve_info_json['epss']:
            if isinstance(epss_entry_item, dict) and 'date' in epss_entry_item and \
               (latest_date is None or epss_entry_item['date'] > latest_date):
                latest_epss_entry = epss_entry_item
                latest_date = epss_entry_item['date']
        
        if latest_epss_entry:
            epss_score = latest_epss_entry.get('epss', 'N/A')
            percentile = latest_epss_entry.get('percentile', 'N/A')
            cve_info += f"EPSS: {epss_score} (Percentile: {percentile})\n"

    if 'cwe' in cve_info_json and cve_info_json['cwe'] and isinstance(cve_info_json['cwe'], list):
        cve_info += f"CWE: {', '.join(cve_info_json['cwe'])}\n"

    # Process enchantments.exploitation
    if 'enchantments' in cve_info_json and \
       isinstance(cve_info_json.get('enchantments'), dict) and \
       'exploitation' in cve_info_json['enchantments'] and \
       isinstance(cve_info_json['enchantments']['exploitation'], dict):
        exploitation_info = cve_info_json['enchantments']['exploitation']
        if 'wildExploited' in exploitation_info:
            exploited_status = 'Yes' if exploitation_info['wildExploited'] else 'No'
            exploitation_line = f"Exploited in the wild: {exploited_status}"
            if exploitation_info['wildExploited'] and \
               'wildExploitedSources' in exploitation_info and \
               isinstance(exploitation_info['wildExploitedSources'], list):
                sources = [source['type'] for source in exploitation_info['wildExploitedSources'] 
                           if isinstance(source, dict) and 'type' in source]
                if sources:
                    exploitation_line += f" (Sources: {', '.join(sources)})"
            cve_info += exploitation_line + "\n"

    # Process references
    if 'references' in cve_info_json and isinstance(cve_info_json['references'], list):
        if cve_info_json['references']:
            cve_info += "References:\n"
            for ref in cve_info_json['references']:
                cve_info += f"  - {ref}\n"
    
    return cve_info

async def _process_dependent_references_json(cve_data_json: dict) -> str:
    """Processes the dependent references from enchantments.dependencies.references, 
    fetches their details from Vulners API, and returns a formatted string."""
    output_str = "\nINFO FROM RELATED SOURCES:\n"

    combined_ids_from_all_idlists = []

    enchantments = cve_data_json.get('enchantments')
    if isinstance(enchantments, dict):
        dependencies = enchantments.get('dependencies')
        if isinstance(dependencies, dict):
            references_list = dependencies.get('references')
            if isinstance(references_list, list):
                if not references_list:
                    output_str += "  No related documents found.\n"
                else:
                    for item in references_list:
                        if isinstance(item, dict):
                            id_list_from_item = item.get('idList')
                            if isinstance(id_list_from_item, list):
                                filtered_ids = [id_val for id_val in id_list_from_item 
                                              if not any(unwanted in str(id_val).lower() 
                                                        for unwanted in ['nvd', 'cvelist', 'vulnrichment'])]
                                combined_ids_from_all_idlists.extend(filtered_ids)
            
            if not combined_ids_from_all_idlists:
                output_str += "  No relevant related document IDs found to fetch further details for.\n"
                return output_str # Return early if no IDs to process

            # API Call to Vulners ID endpoint for combined_ids_from_all_idlists
            api_key = os.getenv("VULNERS_API_KEY")
            if not api_key:
                output_str += "  Error: VULNERS_API_KEY not configured for fetching related document details.\n"
                return output_str

            url = "https://vulners.com/api/v3/search/id"
            # Define fields to retrieve for related documents
            related_doc_fields = ["published", 
                                  "title", 
                                  "href"]
            payload = {
                "id": combined_ids_from_all_idlists,
                "fields": related_doc_fields,
                "apiKey": api_key
            }
            headers = {
                'Content-Type': 'application/json'
            }

            output_str += "  Fetching details for related document IDs...\n"
            try:
                async with httpx.AsyncClient() as client:
                    response = await client.post(url, json=payload, headers=headers)
                    response.raise_for_status()
                    response_data = response.json()

                    if 'data' in response_data and 'documents' in response_data['data']:
                        documents = response_data['data']['documents']
                        found_ids_count = 0
                        if isinstance(documents, dict): # Check if documents is a dict as expected
                            for doc_id_str, doc_content in documents.items():
                                if isinstance(doc_content, dict): # Ensure doc_content is a dict
                                    found_ids_count +=1
                                    output_str += f"    ------------------------------------\n"
                                    output_str += f"    Title: {doc_content.get('title', 'N/A')}\n"
                                    output_str += f"    Link: {doc_content.get('href', 'N/A')}\n"
                                    output_str += f"    Published: {doc_content.get('published', 'N/A')}\n"
                        if found_ids_count == 0:
                            output_str += "    No details found for the provided related document IDs.\n"
                        output_str += f"    ------------------------------------\n"
                    else:
                        output_str += f"    Error: Unexpected API response structure when fetching related document details: {response_data}\n"
            
            except httpx.HTTPStatusError as e:
                output_str += f"    HTTP error occurred: {e.response.status_code} - {e.response.text}\n"
            except httpx.RequestError as e:
                output_str += f"    Request error occurred: {e}\n"
            except json.JSONDecodeError:
                output_str += f"    Error: Failed to decode JSON response from API. Response text: {response.text if 'response' in locals() else 'N/A'}\n"
            except KeyError as e:
                output_str += f"    Error: Key not found in API response - {str(e)}. Expected 'data' and 'documents' keys.\n"
            except Exception as e:
                output_str += f"    An unexpected error occurred: {str(e)}\n"

    return output_str

async def vulners_cve_detailed_info(cve_id: str) -> str:
    """Get CVE information using Vulners API v3. (Mirrors vulners_cve_info functionality).

    Args:
        cve_id: The CVE ID to fetch (e.g., CVE-2023-23397)
    """
    logging.debug(f"Fetching detailed CVE information for: {cve_id} (direct API call and processing)")

    api_key = os.getenv("VULNERS_API_KEY")

    if not api_key:
        logging.warning("VULNERS_API_KEY not found. Please set it.")
        return "Error: VULNERS_API_KEY not configured."
    
    cve_fields = [
        "published",
        "id",
        "description",
        "cvss",
        "epss",
        "cwe",
        "references",
        "enchantments.exploitation",
        "enchantments.dependencies.references"
        ]

    url = "https://vulners.com/api/v3/search/id"
    payload = {
        "id": cve_id,
        "fields": cve_fields, 
        "apiKey": api_key
    }
    headers = {
        'Content-Type': 'application/json'
    }

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(url, json=payload, headers=headers)
            response.raise_for_status()

            response_data = response.json()
            if 'data' in response_data and 'documents' in response_data['data'] and cve_id in response_data['data']['documents']:
                cve_data_for_id = response_data['data']['documents'][cve_id]

                cve_info = _process_cve_json(cve_data_for_id)

                cve_info += await _process_dependent_references_json(cve_data_for_id)

                return cve_info
            else:
                logging.error(f"Unexpected API response structure for {cve_id} in vulners_cve_detailed_info: {response_data}")
                return f"Error: Unexpected API response structure for {cve_id}."

    except httpx.HTTPStatusError as e:
        logging.error(f"HTTP error occurred while fetching detailed info: {e.response.status_code} - {e.response.text}")
        return f"Error: HTTP {e.response.status_code} - {e.response.text}"
    except httpx.RequestError as e:
        logging.error(f"Request error occurred while fetching detailed info: {e}")
        return f"Error: Request failed - {e}"
    except KeyError: # Catching KeyError more broadly here
        response_text_for_log = "Response not available or not valid JSON"
        try:
            if 'response' in locals() and hasattr(response, 'text'):
                response_text_for_log = response.text
        except Exception: # nosec
            pass
        logging.error(f"KeyError while processing detailed info for {cve_id}. Response text: {response_text_for_log}")
        return f"Error: Data not found or unexpected structure for {cve_id} in API response."
    except Exception as e:
        logging.error(f"An unexpected error occurred while fetching detailed info: {e}")
        return f"Error: An unexpected error occurred - {e}"
    
def test_vulners_cve_detailed_info():
    """Test function for vulners_cve_info."""
    # Configure logging for better output
    logging.basicConfig(level=logging.DEBUG)

    # Example CVE ID (replace with a valid one for testing)
    cve_id = "CVE-2025-30400" 

    # Ensure VULNERS_API_KEY is set as an environment variable
    # For example, in your terminal: export VULNERS_API_KEY='YOUR_API_KEY'
    # Or, for testing purposes, you could temporarily set it here (not recommended for production)
    # os.environ['VULNERS_API_KEY'] = 'YOUR_ACTUAL_API_KEY'

    if not os.getenv("VULNERS_API_KEY"):
        print("Please set the VULNERS_API_KEY environment variable to run the test.")
        print("Example: export VULNERS_API_KEY='YOUR_API_KEY'")
        return

    print(f"Testing with CVE ID: {cve_id}")
    result = asyncio.run(vulners_cve_detailed_info(cve_id))
    print(result)

if __name__ == "__main__":
    test_vulners_cve_detailed_info()

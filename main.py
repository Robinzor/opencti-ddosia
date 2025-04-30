from dotenv import load_dotenv
import os
import re
import sys
import time
from datetime import datetime
from typing import Any, Dict, Mapping, Optional

import requests
import stix2
import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable
from tld import get_tld
import urllib3
from dotenv import load_dotenv

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

load_dotenv()

__version__ = "0.0.1"
BANNER = f"""
DDoSia importer, version {__version__}
"""


class DDoSiaConnector:
    @staticmethod
    def _validate_ipv4(ipv4):
        ipv4validator = re.compile(
            "^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        )
        return ipv4validator.match(ipv4)

    @staticmethod
    def _validate_domain(domain):
        domainvalidator = re.compile(
            "^((?!-))(xn\\-\\-)?[a-z0-9][a-z0-9\\-_]{0,61}[a-z0-9]{0,1}(\\.(xn\\-\\-)?([a-z0-9\\-]{1,61}|[a-z0-9\\-]{1,30}\\.[a-z]{2,}))+$"
        )
        return domainvalidator.match(domain)

    def __init__(self):
        print(BANNER)
        self.session = requests.session()
        
        # Create config dictionary from environment variables
        config = {
            "opencti": {
                "url": os.getenv("OPENCTI_API_URL"),
                "token": os.getenv("OPENCTI_API_KEY"),
                "verify_ssl": os.getenv("OPENCTI_VERIFY_SSL", "false").lower() == "true"
            },
            "connector": {
                "id": "ddosia-connector",
                "type": "EXTERNAL_IMPORT",
                "name": "DDoSia Connector",
                "scope": "ddosia",
                "confidence_level": int(os.getenv("DDOSIA_CONFIDENCE_LEVEL", "60")),
                "log_level": "info"
            }
        }
        
        self.helper = OpenCTIConnectorHelper(config)
        
        # Get configuration values
        self.interval = int(os.getenv("DDOSIA_INTERVAL", "300"))
        self.update_existing_data = os.getenv("DDOSIA_UPDATE_EXISTING_DATA", "true").lower() == "true"
        self.score = int(os.getenv("DDOSIA_CONFIDENCE_LEVEL", "60"))
        self.update_frequency = int(os.getenv("DDOSIA_UPDATE_FREQUENCY", "300"))
        
        # Create organization
        external_reference_org = self.helper.api.external_reference.create(
            source_name="witha.name",
            url="https://witha.name/data/",
        )
        self.organization = self.helper.api.identity.create(
            type="Organization",
            name="Circl DDoSia witha.name",
            description="Circl DDoSia witha.name importer",
            externalReferences=[external_reference_org["id"]],
        )

    def get_latest_file(self):
        response = self.session.get("https://witha.name/data/")
        response.raise_for_status()
        
        index_page = response.text
        lines = index_page.splitlines()
        json_files = [
    line for line in lines if 'DDoSia-target-list-full.json' in line]
    
        if not json_files:
            raise ValueError("No DDoSia JSON files found in the index page")

        last_file = json_files[-1].split('href="')[1].split('"')[0]
        return "https://witha.name/data/" + last_file

    def get_label(self, label_value, color="#ffa500"):
        """Controleert of een label bestaat, zo niet wordt het aangemaakt."""
        labels = self.helper.api.label.list(search=label_value)
        for label in labels:
            if label["value"].lower() == label_value.lower():
                return label["id"]
        new_label = self.helper.api.label.create(
            value=label_value, color=color)
        return new_label["id"]

    def create_observable(
    self,
    observable_key,
    observable_value,
    description,
    observable_type,
    external_reference_id,
     labels):
        # Create observable
        current_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        observable = self.helper.api.stix_cyber_observable.create(
            simple_observable_key=observable_key,
            simple_observable_value=observable_value,
            simple_observable_description=f"{description}\nLast update: {current_date}",
            objectMarking=[stix2.TLP_GREEN["id"]],
            externalReferences=[external_reference_id],
            createdBy=self.organization["id"],
            x_opencti_score=self.score,
            x_opencti_create_indicator=True,
            x_opencti_main_observable_type=observable_type,
        )

        # Add labels to the observable with delay between operations
        if observable and labels:
            for label in labels:
                try:
                    label_id = self.get_label(label)
                    if label_id:
                        time.sleep(0.5)  # Add delay between operations
                        self.helper.api.stix_cyber_observable.add_label(
                            id=observable["id"], label_id=label_id)
                except Exception as e:
                    self.helper.log_error(
                        f"Failed to add label {label} to {observable_value}: {str(e)}")
                    time.sleep(0.5)  # Add longer delay after error
                    continue

        return observable

    def collect_targets(self, targets):
        target_attacks = {}

        for target in targets:
            # Validate required fields
            if not all(key in target for key in ['ip', 'host']):
                self.helper.log_warning(
                    f"Missing required fields in target: {target}")
                continue

            ip = target['ip']
            host = target['host']

            # Validate IP and domain
            if not self._validate_ipv4(ip):
                self.helper.log_warning(f"Invalid IP address format: {ip}")
                continue
            if not self._validate_domain(host):
                self.helper.log_warning(f"Invalid domain format: {host}")
                continue

            # Create base key for target
            base_key = f"{ip}_{host}"

            # Create attack details
            attack_details = {
                'type': target.get('type', 'N/A'),
                'method': target.get('method', 'N/A'),
                'port': target.get('port', 'N/A'),
                'use_ssl': target.get('use_ssl', 'N/A'),
                'path': target.get('path', 'N/A'),
                'body': target.get('body', {}).get('value', 'N/A'),
                'headers': target.get('headers', 'N/A')
            }

            # Add attack to target's list of attacks
            if base_key not in target_attacks:
                target_attacks[base_key] = {
                    'ip': ip,
                    'host': host,
                    'attacks': []
                }

            # Check if this specific attack already exists
            if attack_details not in target_attacks[base_key]['attacks']:
                target_attacks[base_key]['attacks'].append(attack_details)

        return target_attacks

    def get_country_from_ip(self, ip):
        """Get country information from IP address using ip-api.com."""
        try:
            response = self.session.get(f"http://ip-api.com/json/{ip}")
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    country = data.get('country', 'Unknown')
                    country_code = data.get('countryCode', 'XX')
                    return f"country-{country_code.lower()}", country
            return None, None
        except Exception as e:
            self.helper.log_error(f"Error getting country for IP {ip}: {str(e)}")
            return None, None

    def get_country_from_tld(self, domain):
        """Get country information from domain TLD."""
        try:
            # Common country TLDs
            tld_to_country = {
                '.nl': ('Netherlands', 'nl'),
                '.uk': ('United Kingdom', 'uk'),
                '.de': ('Germany', 'de'),
                '.fr': ('France', 'fr'),
                '.it': ('Italy', 'it'),
                '.es': ('Spain', 'es'),
                '.ua': ('Ukraine', 'ua'),
                '.ru': ('Russia', 'ru'),
                '.us': ('United States', 'us'),
                '.ca': ('Canada', 'ca'),
                '.au': ('Australia', 'au'),
                '.jp': ('Japan', 'jp'),
                '.cn': ('China', 'cn'),
                '.in': ('India', 'in'),
                '.br': ('Brazil', 'br'),
                '.mx': ('Mexico', 'mx'),
                '.za': ('South Africa', 'za'),
                '.se': ('Sweden', 'se'),
                '.no': ('Norway', 'no'),
                '.dk': ('Denmark', 'dk'),
                '.fi': ('Finland', 'fi'),
                '.pl': ('Poland', 'pl'),
                '.cz': ('Czech Republic', 'cz'),
                '.sk': ('Slovakia', 'sk'),
                '.hu': ('Hungary', 'hu'),
                '.ro': ('Romania', 'ro'),
                '.bg': ('Bulgaria', 'bg'),
                '.gr': ('Greece', 'gr'),
                '.tr': ('Turkey', 'tr'),
                '.il': ('Israel', 'il'),
                '.ae': ('United Arab Emirates', 'ae'),
                '.sa': ('Saudi Arabia', 'sa'),
                '.eg': ('Egypt', 'eg'),
                '.za': ('South Africa', 'za'),
                '.ke': ('Kenya', 'ke'),
                '.ng': ('Nigeria', 'ng'),
                '.ar': ('Argentina', 'ar'),
                '.cl': ('Chile', 'cl'),
                '.co': ('Colombia', 'co'),
                '.pe': ('Peru', 'pe'),
                '.ve': ('Venezuela', 've'),
                '.nz': ('New Zealand', 'nz'),
                '.sg': ('Singapore', 'sg'),
                '.my': ('Malaysia', 'my'),
                '.th': ('Thailand', 'th'),
                '.vn': ('Vietnam', 'vn'),
                '.kr': ('South Korea', 'kr'),
                '.tw': ('Taiwan', 'tw'),
                '.hk': ('Hong Kong', 'hk'),
                '.id': ('Indonesia', 'id'),
                '.ph': ('Philippines', 'ph'),
            }
            
            # Extract TLD from domain
            tld = '.' + domain.split('.')[-1].lower()
            
            if tld in tld_to_country:
                country_name, country_code = tld_to_country[tld]
                return f"country-{country_code}", country_name
            
            return None, None
        except Exception as e:
            self.helper.log_error(f"Error getting country from TLD for domain {domain}: {str(e)}")
            return None, None

    def get_or_create_country(self, country_code, country_name):
        """Get or create a Country object."""
        try:
            # Search for existing country
            countries = self.helper.api.location.list(
                filters={
                    "mode": "and",
                    "filters": [
                        {"key": "entity_type", "values": ["Country"]},
                        {"key": "name", "values": [country_name]}
                    ],
                    "filterGroups": []
                }
            )
            
            if countries:
                return countries[0]
            
            # Create new country if not found
            country = self.helper.api.location.create(
                name=country_name,
                description=f"Country {country_name} ({country_code})",
                latitude=0,  # Default values
                longitude=0,
                createdBy=self.organization["id"],
                objectMarking=[stix2.TLP_GREEN["id"]],
                x_opencti_location_type="Country"
            )
            return country
        except Exception as e:
            self.helper.log_error(f"Error creating/getting country {country_name}: {str(e)}")
            return None

    def process_target(self, target_data, external_reference_id):
        try:
            ip = target_data['ip']
            host = target_data['host']
            attacks = target_data['attacks']

            self.helper.log_info(f"Processing target: {host} ({ip})")

            # Check if we already have this target
            domain_obs_list = self.helper.api.stix_cyber_observable.list(
                filters={
                    "mode": "and",
                    "filters": [
                        {"key": "entity_type", "values": ["Domain-Name"]},
                        {"key": "value", "values": [host]}
                    ],
                    "filterGroups": []
                }
            )
            
            if domain_obs_list:
                # Get the first observable
                domain_obs = domain_obs_list[0]
                # Check if it was updated today
                updated_at = domain_obs.get('updated_at', '')
                current_date = datetime.now().strftime("%Y-%m-%d")
                if updated_at.startswith(current_date):
                    self.helper.log_info(f"Target {host} was already updated today, skipping")
                    return True

            # Create base labels
            labels = ["ddosia", "ddos"]

            # Add unique attack types as labels
            for attack in attacks:
                attack_type = attack.get('type')
                if attack_type and attack_type != 'N/A':
                    label = f"attack-type-{attack_type.lower()}"
                    if label not in labels:  # Ensure we don't add duplicates
                        labels.append(label)

            # Get country information from TLD
            country_label, country_name = self.get_country_from_tld(host)
            if country_label:
                labels.append(country_label)
                country_info = f" ({country_name})"
                
                # Get or create country object
                country_code = country_label.split('-')[1]  # Extract code from 'country-nl'
                country = self.get_or_create_country(country_code, country_name)
            else:
                country_info = ""
                country = None

            # Log the labels we're about to use
            self.helper.log_info(f"Labels for {host} ({ip}): {labels}")

            # Create IP observable
            self.helper.log_info(f"Creating/updating IP observable for {ip}")
            ip_obs = self.create_observable(
                "IPv4-Addr.value",
                ip,
                f"DDoSia target {ip}{country_info}",
                "IPv4-Addr",
                external_reference_id,
                labels
            )

            if not ip_obs:
                self.helper.log_error(f"Failed to create IP observable for {ip}")
                return False

            # Create Domain observable
            self.helper.log_info(f"Creating/updating Domain observable for {host}")
            domain_obs = self.create_observable(
                "Domain-Name.value",
                host,
                f"DDoSia target {host}{country_info}",
                "Domain-Name",
                external_reference_id,
                labels
            )

            if not domain_obs:
                self.helper.log_error(f"Failed to create Domain observable for {host}")
                return False

            # Create relationship between domain and IP
            self.helper.log_info(f"Creating relationship between {host} and {ip}")
            self.helper.api.stix_core_relationship.create(
                fromId=domain_obs["id"],
                toId=ip_obs["id"],
                relationship_type="resolves-to",
                createdBy=self.organization["id"]
            )

            # Create relationship between domain and country if country was found
            if country:
                self.helper.log_info(f"Creating relationship between {host} and country {country_name}")
                self.helper.api.stix_core_relationship.create(
                    fromId=domain_obs["id"],
                    toId=country["id"],
                    relationship_type="related-to",
                    createdBy=self.organization["id"]
                )

            self.helper.log_info(f"Successfully processed target {host} ({ip})")
            return True

        except Exception as e:
            self.helper.log_error(f"Error processing target {host} ({ip}): {str(e)}")
            return False

    def run(self):
        last_update = 0
        while True:
            try:
                current_time = time.time()

                # Check if it's time to update
                if current_time - last_update >= self.update_frequency:
                    self.helper.log_info("Starting DDoSia connector...")
                    # Get latest file URL
                    latest_url = self.get_latest_file()
                    self.helper.log_info(f"Fetching data from: {latest_url}")
                    # Create external reference for this update
                    external_reference = self.helper.api.external_reference.create(
                        source_name="witha.name",
                        url=latest_url
                    )

                    # Fetch and parse data
                    response = self.session.get(latest_url)
                    if response.status_code != 200:
                        raise ValueError(f"Failed to fetch target list: HTTP {response.status_code}")
                    
                    json_data = response.json()
                    
                    # Get targets from the correct field
                    targets = json_data.get('targets', [])
                    if not targets:
                        self.helper.log_warning("No targets found in the JSON data")
                        time.sleep(self.interval)
                        continue
                    
                    # First collect all targets and their attacks
                    target_attacks = self.collect_targets(targets)
                    self.helper.log_info(f"Collected {len(target_attacks)} targets")

                    # Process each target
                    success_count = 0
                    failure_count = 0
                    for target_data in target_attacks.values():
                        if self.process_target(target_data, external_reference["id"]):
                            success_count += 1
                        else:
                            failure_count += 1

                    self.helper.log_info(f"Import completed: {success_count} targets processed successfully, {failure_count} failed")
                    last_update = current_time

                # Sleep for the interval time
                self.helper.log_info(f"Sleeping for {self.interval} seconds...")
                time.sleep(self.interval)

            except Exception as e:
                self.helper.log_error(f"Error in main loop: {str(e)}")
                time.sleep(self.interval)


if __name__ == "__main__":
    try:
        connector = DDoSiaConnector()
        connector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)

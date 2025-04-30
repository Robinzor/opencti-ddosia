# DDoSia Connector for OpenCTI

A connector developed by [Robinzor](https://github.com/Robinzor) that imports DDoS attack data from witha.name into OpenCTI, creating observables and relationships for targeted domains and IP addresses.

## Features

- Imports DDoS attack data from witha.name
- Creates Domain-Name and IPv4-Addr observables
- Adds country information based on TLD
- Creates relationships between domains and IPs
- Adds attack type labels
- Updates existing observables with new information

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `OPENCTI_API_URL` | URL of your OpenCTI instance | Required |
| `OPENCTI_API_KEY` | API key for OpenCTI | Required |
| `DDOSIA_INTERVAL` | Interval between checks in seconds | 300 |
| `DDOSIA_UPDATE_EXISTING_DATA` | Whether to update existing data | true |
| `DDOSIA_CONFIDENCE_LEVEL` | Confidence level for created observables | 60 |
| `DDOSIA_UPDATE_FREQUENCY` | How often to check for updates in seconds | 300 |

### Example .env file

Create a file named `.env` with the following content:

```bash
# OpenCTI Configuration
OPENCTI_API_URL=
OPENCTI_API_KEY=

# DDoSia Connector Configuration
DDOSIA_INTERVAL=300
DDOSIA_UPDATE_EXISTING_DATA=true
DDOSIA_CONFIDENCE_LEVEL=60
DDOSIA_UPDATE_FREQUENCY=300
```

Replace the empty values for `OPENCTI_API_URL` and `OPENCTI_API_KEY` with your actual OpenCTI credentials.

## Installation

### Using Docker

1. Clone the repository:
```bash
git clone https://github.com/Robinzor/opencti-ddossia.git
cd opencti-ddossia
```

2. Create a `.env` file with your configuration

3. Build and run with Docker Compose:
```bash
docker-compose up -d
```

### Using GitHub Container Registry

The container is automatically built and pushed to GitHub Container Registry on each push to main.

To use the pre-built container:

```bash
docker pull ghcr.io/robinzor/opencti-ddossia:latest
```

## Development

### Local Development

1. Create a virtual environment:
```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the connector:
```bash
python main.py
```

### Testing

The connector includes basic error handling and logging. Check the logs for any issues:

```bash
docker-compose logs -f
```

## Data Model

For each target, the connector creates:

1. Observables:
   - Domain-Name for the target domain
   - IPv4-Addr for the target IP

2. Relationships:
   - Domain-Name `resolves-to` IPv4-Addr
   - Domain-Name `related-to` Country (based on TLD)

3. Labels:
   - Attack types (e.g., "attack-type-tcp")
   - Country codes (e.g., "country-nl")

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

- [Robinzor](https://github.com/Robinzor) 
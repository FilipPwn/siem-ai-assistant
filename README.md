# AI-Powered Security Alert Analysis System

An automated system that leverages AI to analyze security alerts from Elastic Security, providing intelligent triage and analysis through GPT-4.

## 🌟 Features

- **Automated Alert Analysis**: Processes security alerts from Elastic Security using GPT-4
- **Intelligent Triage**: Provides severity assessments and actionable insights
- **MITRE ATT&CK Integration**: Analyzes alerts in context of MITRE ATT&CK framework
- **Detailed Documentation**: AI generates comprehensive analysis notes for each alert
- **Seamless Integration**: Works with Elasticsearch and Kibana APIs
- **Debug Logging**: Detailed logging for troubleshooting and audit trails

## 🚀 Getting Started

### Prerequisites

- Python 3.8+
- Access to OpenAI API
- Elasticsearch/Kibana instance
- Required Python packages (see Installation)

### Installation

1. Clone the repository
2. Install required packages:

```
pip install openai elasticsearch python-dotenv pyyaml
```

3. Create a `.env` file with your credentials:
```
ELASTIC_URL=https://your-elasticsearch-instance
KIBANA_URL=https://your-kibana-instance
ELASTIC_USERNAME=your-username
ELASTIC_PASSWORD=your-password
OPENAI_API_KEY=your-openai-key
```

## 🔧 Configuration

The system uses three main connector classes:

1. **KibanaConnector**: Interfaces with Kibana API for rule management and note addition
2. **ElasticsearchConnector**: Retrieves security signals from Elasticsearch
3. **AISecurityAnalyst**: Processes alerts using OpenAI's GPT-4

### AI Analysis Configuration

The AI analyst can be configured with:
- Custom OpenAI model selection
- Temperature adjustment for response randomness
- Customizable prompt templates

## 🏃‍♂️ Usage

Run the main script to start processing alerts:

```python main.py```

The system will:
1. Fetch detection rules from Kibana
2. Retrieve security signals from Elasticsearch
3. Process each signal with AI analysis
4. Add detailed notes back to Kibana

## 📊 Output Format

The AI analysis includes:
- Severity Assessment
- Rule Description
- Host and User Context
- Detailed Technical Analysis
- Recommended Actions

## 🔒 Security Considerations

- SSL verification can be configured for both Elasticsearch and Kibana connections
- Credentials are stored securely in environment variables
- Debug logs are saved in NDJSON format for audit trails

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- OpenAI for GPT-4 API
- Elastic for Elasticsearch and Kibana
- MITRE for the ATT&CK framework
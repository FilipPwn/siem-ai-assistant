from typing import Dict, List, Optional
import openai
import json
import yaml
from datetime import datetime

class AISecurityAnalyst:
    def __init__(
        self,
        openai_api_key: str,
        model: str = "gpt-4o",
        temperature: float = 0.3
    ):
        """
        Initialize AI Security Analyst with OpenAI credentials.
        
        Args:
            openai_api_key: OpenAI API key
            model: OpenAI model to use (default: gpt-4)
            temperature: Model temperature (default: 0.3)
        """
        self.client = openai.OpenAI(api_key=openai_api_key)
        self.model = model
        self.temperature = temperature
        self.log_file = "logs.txt"

    def _create_signal_prompt(self, signal: Dict) -> str:
        """
        Create a prompt for the AI model based on the signal data.
        
        Args:
            signal: Security signal dictionary containing alert details
        """
        # Extract process details from source
        process = signal.get('source', {}).get('process', {})
        parent_process = process.get('parent', {})
        
        # Extract alert details from source.kibana.alert
        kibana_alert = signal.get('source', {}).get('kibana', {}).get('alert', {})
        rule_params = kibana_alert.get('rule', {}).get('parameters', {})
        
        # Get host info from source
        host = signal.get('source', {}).get('host', {})
        
        # Get user info from source
        user = signal.get('source', {}).get('user', {})
        
        return f"""Analyze the following security alert and provide a triage assessment:

        Alert Details:
        - Rule Name: {kibana_alert.get('rule', {}).get('name', 'N/A')}
        - Severity: {rule_params.get('severity', 'N/A')}
        - Risk Score: {rule_params.get('risk_score', 'N/A')}
        - Description: {rule_params.get('description', 'N/A')}
        - Timestamp: {signal.get('source', {}).get('@timestamp', 'N/A')}

        Process Information:
        - Name: {process.get('name', 'N/A')}
        - Command Line: {process.get('command_line', 'N/A')}
        - Working Directory: {process.get('working_directory', 'N/A')}
        - Parent Process: {parent_process.get('name', 'N/A')}
        - Parent Command Line: {parent_process.get('command_line', 'N/A')}

        User Context:
        - Username: {user.get('name', 'N/A')}
        - Domain: {user.get('domain', 'N/A')}

        Host Information:
        - Hostname: {host.get('hostname', 'N/A')}
        - OS: {host.get('os', {}).get('name', 'N/A')}

        MITRE ATT&CK:
        {yaml.dump(rule_params.get('threat', []), default_flow_style=False)}

        Please provide:
        1. Severity Assessment (Critical/High/Medium/Low) with short explanation
        2. Short description of the rule and its purpose
        3. Short summary of host and user context in a table
        4. Detailed analysis of the alert with highlighting key fields and explaining what that key data mean (like explaining process with arguments, files and registry)
        5. Recommended immediate actions

        Use markdown formatting for the response.
        """

    def _log_debug(self, message: str, data: any) -> None:
        """Log debug information to file in NDJSON format."""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "message": message,
            "data": data
        }
        with open(self.log_file, 'a') as f:
            f.write(json.dumps(log_entry) + "\n")

    def analyze_signal(self, signal: Dict) -> Dict:
        """
        Analyze a security signal using the AI model.
        
        Args:
            signal: Security signal dictionary from Elasticsearch
        
        Returns:
            Dictionary containing AI analysis results
        """
        prompt = self._create_signal_prompt(signal)
        
        # Log the input signal and prompt
        self._log_debug("Input Signal:", signal)
        self._log_debug("Generated Prompt:", prompt)
        
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": "You are an expert security analyst. Analyze the security alert and provide concise, actionable insights."},
                {"role": "user", "content": prompt}
            ],
            temperature=self.temperature
        )

        # Log the AI response
        self._log_debug("AI Response:", response.model_dump())
        
        return {
            "signal_id": signal["id"],
            "analysis": response.choices[0].message.content,
            "model_used": self.model,
            "timestamp": signal["source"].get("@timestamp")
        }
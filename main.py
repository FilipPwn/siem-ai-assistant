from dotenv import load_dotenv
import os
from connectors.kibana import KibanaConnector
from connectors.elasticsearch import ElasticsearchConnector
from connectors.ai import AISecurityAnalyst

# Load environment variables
load_dotenv()
kibana = KibanaConnector(
    host=os.getenv('KIBANA_URL'),
    space='soc',
    username=os.getenv('ELASTIC_USERNAME'),
    password=os.getenv('ELASTIC_PASSWORD'),
    verify_ssl=False 
)
elastic = ElasticsearchConnector(
    host=os.getenv('ELASTIC_URL'),
    username=os.getenv('ELASTIC_USERNAME'),
    password=os.getenv('ELASTIC_PASSWORD'),
    verify_ssl=False
)
ai_analyst = AISecurityAnalyst(
    openai_api_key=os.getenv('OPENAI_API_KEY'),
    model="gpt-4o"
)

def main():
    rules = kibana.get_all_detection_rules()
    print(f"Found {len(rules)} rules")
    
    signals = elastic.get_signals(space='soc', days=30)
    print(f"Found {len(signals)} signals")
    
    # Process each signal with AI analysis
    for signal in signals:
        try:
            # Get AI analysis
            analysis = ai_analyst.analyze_signal(signal)
            
            # Format the note with AI analysis
            note_text = f"""
            AI Security Analysis            

            {analysis['analysis']}

            Signal ID: {signal['id']}
            Analysis Timestamp: {analysis['timestamp']}
            Model Used: {analysis['model_used']}
            """
            # Add the analysis as a note to the alert
            kibana.add_note(event_id=signal['id'], note_text=note_text)
            print(f"✓ Processed signal {signal['id']}")
            
        except Exception as e:
            print(f"✗ Error processing signal {signal['id']}: {str(e)}")

if __name__ == "__main__":
    main()
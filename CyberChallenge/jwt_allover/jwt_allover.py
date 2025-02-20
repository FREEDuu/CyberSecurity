import pyshark
from datetime import datetime
import base64
import json

def extract_exp_from_jwt(token):
    try:
        header, payload, signature = token.split('.')
        
        # Decode in Base64 
        padded_payload = payload + '=' * (-len(payload) % 4)  # Fix padding
        decoded_payload = base64.urlsafe_b64decode(padded_payload).decode('utf-8')
        
        # Convert JSON payload to dictionary
        payload_data = json.loads(decoded_payload)
        
        return payload_data.get('exp', None), payload_data.get('nbf', None)
    except Exception as e:
        print(f"Error decoding JWT: {e}")
        return None, None

def check_time(token):
    timestamp, notbefore = extract_exp_from_jwt(token)
    if timestamp:
        target_dt = datetime(2022, 6, 1, 12, 0, 0)  # 2022-06-01 12:00: timestamp given in CC chall
        dt_exp = datetime.fromtimestamp(timestamp)  # Convert from int timestamo to datetime
        dt_nbf = datetime.fromtimestamp(notbefore) 
        print(dt_exp, target_dt, dt_nbf)
        return dt_exp > target_dt and dt_nbf < target_dt # check if the token is valid nbf = not before !!
    return False

def check_http_packets(pcap_file):

    cap = pyshark.FileCapture(pcap_file, display_filter='http')

    for packet in cap:
        try:
            if hasattr(packet, 'http'):
                http_layer = packet.http
                
                if hasattr(http_layer, 'authorization') and 'Bearer' in http_layer.authorization:
                    token = http_layer.authorization.split('Bearer ')[1]
                    
                    print(f"Try this token --> Token: {token}")
                    if check_time(token):  
                        print('JWT FOUND:', token)
                        break  
        except Exception as e:
            print(f"Error processing packet: {e}")

    cap.close()


pcap_file = "chall4.pcap" 
check_http_packets(pcap_file)

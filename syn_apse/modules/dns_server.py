import subprocess
import threading
import os

def start_dns_server(port=80):
    """
    This function locally serves an html route as a 
    redirect endpoint for a successfull DNS spoofing attack.
    """


    try:
        # Read the HTML file
        with open('../routes/index.html', 'r') as f:
            html_content = f.read()
        
        # Write to current directory for the server
        with open('index.html', 'w') as f:
            f.write(html_content)
        
        # Start server
        subprocess.run(["python3", "-m", "http.server", str(port)], check=True)
        
    except FileNotFoundError:
        print("[ERROR] ./routes/index.html not found!")
    except Exception as e:
        print(f"[DNS] Server error: {e}")
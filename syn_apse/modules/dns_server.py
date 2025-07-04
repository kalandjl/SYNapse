import subprocess
import threading
import os

def start_dns_server(port=80):
    """
    This function locally serves an html route as a 
    redirect endpoint for a successfull DNS spoofing attack.
    """


    def run_server():
        try:
            # Change to routes directory
            original_dir = os.getcwd()
            os.chdir('../routes')
            
            # Start server from routes directory
            subprocess.run(["python3", "-m", "http.server", str(port)], check=True)
            
        except FileNotFoundError:
            print("[ERROR] ./routes directory not found!")
        except Exception as e:
            print(f"[DNS] Server error: {e}")
        finally:
            # Change back to original directory
            os.chdir(original_dir)
    
    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()
    return server_thread
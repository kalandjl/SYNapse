import subprocess

index_html="""
<!DOCTYPE html>
<html>
    <head>
        <title>
            PWNED
        </title>
    </head>
    <body>
        <h1>
            You have been spoofed by SYNapse.
        </h1>
        <a href="https://www.github.com/kalandjl/SYNapse">
            How'd we do it?
        </a>
    </body>
</html>
"""

def start_dns_server(port=80):
    """
    This function locally serves an html route as a 
    redirect endpoint for a successfull DNS spoofing attack.
    """


    try:
        
        # Start server
        subprocess.run(["python3", "-m", "http.server", str(port)], check=True)
        
    except FileNotFoundError:
        print("[ERROR] ./routes/index.html not found!")
    except Exception as e:
        print(f"[DNS] Server error: {e}")
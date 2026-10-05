from mcp.server.mcpserver import MCPServer

app = MCPServer("test-server")

@app.tool()
def test_tool() -> str:
    """Returns the current system status."""
    return "OK"

if __name__ == "__main__":
    app.run(transport="stdio")

import typer

app = typer.Typer()

@app.command()
def scan(target: str):
    print(f"Scanning {target}")

if __name__ == "__main__":
    app()

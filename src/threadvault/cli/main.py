import typer

app = typer.Typer(help="threadvault: portable AI conversation threads")


@app.callback()
def main() -> None:
    """threadvault CLI (commands are added in later phases)."""

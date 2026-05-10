from __future__ import annotations

import click

from register_cmd import run_register
from connect_cmd import run_connect


@click.group()
def cli() -> None:
    pass


@cli.command("register")
@click.argument("config_file", type=click.Path(exists=True))
def register_cmd(config_file: str) -> None:
    run_register(config_file)


@cli.command("connect")
@click.argument("config_file", type=click.Path(exists=True))
def connect_cmd(config_file: str) -> None:
    run_connect(config_file)


if __name__ == "__main__":
    cli()

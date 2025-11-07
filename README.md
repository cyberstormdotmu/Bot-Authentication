# Web Bot Auth Python

![GitHub License](https://img.shields.io/github/license/cyberstormdotmu/bot-authentication)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

Implementation of Web Bot Auth in Python. 

Read the [story behind Web Bot Auth](https://blog.cloudflare.com/web-bot-auth/), or find out more about how to
[Identify Bots with HTTP Message Signatures](https://http-message-signatures-example.research.cloudflare.com/).

## Installation

Install via `uv`
```shell
uv add bot-auth
```

or `pip`
```shell
pip install bot-auth
```

## Development

### Requirements

* [Python 3.13](https://www.python.org/downloads/)
* [uv](https://docs.astral.sh/uv/getting-started/installation/) - Python package manager

### Build

To build bot-auth package

```shell
uv sync

uv build
```

### Run examples
In the `examples` folder there are examples of how to use Bot Auth with popular scraping libraries like
[scrapy](https://www.scrapy.org/) or [crawl4ai](https://crawl4ai.com/).

Each example is a project, see the README in each example folder to run it.

```shell
cd examples/crawl4ai-hook
uv run main.py
```

### Lint

This codebase uses [ruff](https://docs.astral.sh/ruff/) and [Black](https://black.readthedocs.io/en/stable/index.html) for linting.

To run a check, use

```shell
uv run ruff check .
uv run black --check .
```

To format the codebase

```shell
uv run ruff format .
uv run black .
```

## Security Considerations

This software has not been audited. Please use at your sole discretion.

## License

This project is under the Apache 2.0 license.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you shall
be Apache 2.0 licensed as above, without any additional terms or conditions.

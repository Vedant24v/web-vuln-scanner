"""
uvicorn launcher with SelectorEventLoop factory — required for psycopg async on Windows.
Usage: python run.py
"""
import selectors
import asyncio
import uvicorn

def main():
    config = uvicorn.Config(
        "backend.main:app",
        host="0.0.0.0",
        port=8000,
        loop="asyncio",
        workers=1,
    )
    server = uvicorn.Server(config)

    # Force SelectorEventLoop — uvicorn's own loop setup will respect loop_factory
    asyncio.run(
        server.serve(),
        loop_factory=lambda: asyncio.SelectorEventLoop(selectors.SelectSelector()),
    )

if __name__ == "__main__":
    main()

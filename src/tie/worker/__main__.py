import asyncio

from tie.worker.pipeline import run_worker_loop

if __name__ == "__main__":
    asyncio.run(run_worker_loop())
from tls_scan.main import async_main
import asyncio

loop = asyncio.get_event_loop()
loop.run_until_complete(async_main("177.71.128.0/17", 50))
loop.close()

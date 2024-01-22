# echo-client.py

import sys
import trio

PORT = 20201


async def sender(client_stream):
    print("sender: started!")
    # while True:
    data = b"Toma essa pacote"
    print(f"sender: sending {data!r}")
    await client_stream.send_all(data)
    # await trio.sleep(1)


async def receiver(client_stream):
    print("receiver: started!")
    async for data in client_stream:
        print(f"receiver: got data {data!r}")
    print("receiver: connection closed")
    sys.exit()


async def parent():
    print(f"parent: connecting to 127.0.0.1:{PORT}")
    client_stream = await trio.open_tcp_stream("127.0.0.1", PORT)
    async with client_stream:
        async with trio.open_nursery() as nursery:

            nursery.start_soon(sender, client_stream)

            nursery.start_soon(receiver, client_stream)


trio.run(parent)
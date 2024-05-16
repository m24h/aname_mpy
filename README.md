# aname_mpy
Asynchronous domain name resolve module for Micropython, method like socket.getaddrinfo() are provided.

Now there's no need to worry about that getaddrinfo() will sometimes block your program. On small devices, full asynchronous is necessary.  

Powerful nslookup() is provided too, which will return all information retrieved from DNS server.

This module can not directly run in cpython. But if you need to run it on cpython, at first you need to explicitly provide the DNS server address (currently obtained through the network module of Micropython, which does not exist on CPython), and the sencond thing is that you need to modify this module, using asyncio.sleep() instead of uasyncio.sleep_ms() (but the latter does not need to translate floating-point numbers, which is more appropriate on Micropython).

Usage/Example:

```python
import aname
import asyncio
asyncio.run(aname.getaddrinfo('pool.ntp.org',123))

```


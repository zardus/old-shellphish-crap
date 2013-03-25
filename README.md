shellphish
==========

# format.py

So, we wrote a little format string generator last hack meeting. I got it into my head to improve on it, and here is the result. It's pretty awesome:

```python
awesome_string = format_string_fuckyeah(writes, byte_offset, string_size, printed_count)
```
where writes is: ( ( address1, value1, size_of_write), (address2, value2, size_of_write), ... )

Now, awesome_string is a format string that'll do the given writes. The improvements are:

- size_of_write can be any power of 2. YES, this means that the format string generator supports writing a byte at a time. This creates a longer format string but produces much less output. It can even mix write sizes (let's say you want to zero-out a whole word by writing 0 to it, then fill in only what you need)!
- writes can contain as many entries as you want. If you have enough room in the format string, it can a whole shellcode or whatever.
- the writes will happen in the order that you give them. Additionally, the format strings can write descending values by overflowing the character counter. The result is that you might end up outputing a lot if you pass an unsorted list, but sorting is left as an exercise to the user (ie, "writes = sorted(writes, key = lambda x: x[1])")
- the generator should be able to produce format strings for 8-bit, 16-bit, 32-bit, and 64-bit architectures. I only tested on 32-bit.
- there is an optional debug argument which'll print %x instead of %n so that you can print the address that you'll be trying to overwrite (this helps in finding the stupid offset)

There's also a helper function:

```python
chunked_writes = chunk(writes, wordsize, chunksize)
```
this time, writes is ( ( address1, value1), (address2, value2), ... ), all of wordsize size

This'll chunk your writes (each of which is of size wordsize) into writes of chunksize, and sort them. Useful for chunking up a shellcode into bytes and writing it one byte at a time, maybe.

Things on the todo list:
- automatically find the offset somehow. We could write a bruteforcer (YEEESSSS) that takes a function that takes a format string and drives the service in question to utilize that format string or something. In the general case, of course, this is impossible. Alternatively, we could look into making a GDB script that could maybe do this.

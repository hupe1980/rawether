+++
title = "Event loops and async"
description = "Use a rawether socket in an event loop: AsFd and AsRawFd, non-blocking receive, poll, mio and a tokio AsyncFd example, without an async runtime dependency in the crate."
weight = 80

[extra]
group = "Guides"
+++

rawether has no async runtime dependency. A `Socket` is a file descriptor that becomes readable when frames are waiting, so any event loop can drive it: `poll`, `epoll`, `kqueue`, mio or tokio.

## The pattern

1. Open the socket with `.nonblocking(true)`, or call `set_nonblocking(true)` later.
2. Register `sock.as_fd()` (or `as_raw_fd()`) for readability.
3. When it is readable, call `try_recv()` until it returns `Ok(None)`.
4. Wait again.

Step 3 matters with edge-triggered loops (epoll in `EPOLLET` mode, mio, tokio): you are woken once per change, not once per frame, so drain everything that is waiting.

## tokio

```rust
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;

#[tokio::main(flavor = "current_thread")]
async fn main() -> std::io::Result<()> {
    let sock = rawether::Config::new("eth0").ethertypes(&[0x88f7]).nonblocking(true).open()?;
    rawether::drop_capabilities()?;
    // SAFETY: a `Socket` owns its descriptor until it is dropped, and `as_raw_fd`
    // always returns that one.
    let mut sock = unsafe { AsyncFd::register_with_interest(sock, Interest::READABLE) }?;

    loop {
        let mut ready = sock.readable_mut().await?;
        // Drain everything that is waiting, then wait for the next wake-up.
        while let Some(p) = ready.get_inner_mut().try_recv()? {
            println!("{} octets, {:?}", p.data().len(), p.timestamp());
        }
        ready.clear_ready();
    }
}
```

This needs tokio's `net` and `rt` features. Each `Packet` borrows the socket only inside the `while let` body, so the borrow checker keeps you from holding a frame across an `.await`. Sending needs only `&Socket`, so `ready.get_inner().send(&frame)` works while you hold the guard. Older tokio releases spell the constructor `AsyncFd::with_interest`.

## A dedicated thread

For the lowest latency, a blocking receive on its own thread is often simplest. It wakes exactly when a frame or block arrives:

```rust
std::thread::spawn(move || -> std::io::Result<()> {
    loop {
        if let Some(p) = sock.recv(None)? {
            handle(p.data());
        }
    }
});
```

`Socket` is `Send`, so it can move to that thread. It is not `Sync`: receiving needs `&mut`, so one thread owns the receive side.

On Linux, call `drop_capabilities()` before spawning threads. Capabilities are per thread, and threads spawned afterwards inherit the empty sets.

## Ring readiness

On the ring path, the descriptor becomes readable when the kernel hands over a block. With the default 1 ms `retire_ms`, a lone frame wakes you within about a millisecond. A burst arrives as a few full blocks, many frames per wake-up. If you need sub-millisecond wake-ups for sparse traffic, use `RxMode::Plain`.

# Onioncloud
------

## Introduction

Onioncloud is an attempt at creating cloud-ish onion service.
The aim of this project is to:

1. Reimplement Tor protocol with cloud in mind.

   That means using mindset, goals, and resources typically available in cloud deployment,
   such as shared database, serverless, horizontal scaling, caching, etc.
2. Implement gateway towards already existing web server.
3. Implement workers library that can be seamlessly integrated into ordinary Rust web server.

## Plan

1. Essentially rewrite Arti (again).

   Unlike Arti, the scope of Onioncloud is strictly limited to onion services.
   This allows us to do things the way Arti can't,
   like exposing stable, highly extensible, boilerplate not included, yet powerful API
   to be then consumed by the actual high-level Onioncloud stuff.

2. Implement Onioncloud initiator and workers.
3. ???
4. Profit!

## Possibly Asked Questions

### Why create this project?

Can't tell you much. Let's just say it was revealed in a dream.

### Why don't you simply fork Arti?

To achieve what we want, forking Arti is not an option.
We need to be able to go deep into Tor protocol itself
and modify it to our purposes.

To put it simply, Arti's low-level code is fucked.

### What about projects like EOTK?

EOTK is nice and all, but relying on C Tor limits it's scalability.

### What about Oniux?

It's parallelization, AKA horizontal scaling. Also it's client/user applications only.

### How it (will) works?

Basically, we aim to separate initiator circuit and rendezvous circuits to different machines.
That way, we can implement things like: load balancing, auto scaling, multi tenancy, etc.
Communication between initiator and workers are left to user (probably a form of pubsub/event bus).

### License?

Since this project is _heavily_ inspired by Arti, we'll use the same license of Apache 2.0.
We would _love_ to use stronger license like LGPL, but the ramifications are _unknown._

### What is the design policy/language?

Our policy in designing this project is as follows:
- We don't believe in "splitting into bunch of small crates then glue up everything".
  It's simply too much headache for marginal compile time speedup.
  Instead, this project will be split up into 3 layer/crates:
  1. Low-level crate: Contains things needed to parse and handle Tor protocol.
     Cryptography code also lives here.
  2. Mid-level crates: Contains implementation of Tor protocol.
     It may be split up into relay, user, hidden service, etc.
  3. High-level crates: Glue low-level and mid-level and provide ready-to-use API.
     This is where actual onioncloud implementation will reside.
- Commits are history, not a story. Don't erase it, keep it real.
- Test implementation to ensure correct behavior and cover edge cases.
- Not using coverage as guiding principle, as it's too much burden.
- Use proptest to make testing edge case easier.
  In the future we might use fuzzing to further test code.
- Use sans-io to make protocol implementation and testing easier.
  Our variation/deviation of sans-io is as follows:
  - I/O is using `WouldBlock` error code to signal yielding/pending, instead of passing buffers around.
    This simplifies I/O and allows for more traditional sync IO code to handle async IO (to some degree).
  - Output of event handling is bundled into one return value, instead of calling a poll functions (like timer/timeout).
    Simplifies `Handle` trait and allows future extensibility at the cost of complex return value.
- Use async, but make it executor independent.
- Message passing/channels async model to simplify managers/runtime.
- No async trait/AFIT, it's PITA to reason about.
- `zerocopy` for parsing packets/cells.

Future contributors _must_ follows these policy. Future ones might be added.

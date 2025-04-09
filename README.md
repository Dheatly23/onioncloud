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

### License?

Since this project is _heavily_ inspired by Arti, we'll use the same license of Apache 2.0.
We would _love_ to use stronger license like LGPL, but the ramifications are _unknown._

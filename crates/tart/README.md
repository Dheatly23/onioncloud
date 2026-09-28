# Onioncloud TART (Test Async RunTime)
--------------------------------------

Klapping them taart cheeks :)

## Introduction

`onioncloud-tart` is an async runtime focused on testing and fuzzing async code.
It's design goals are:

- Minimal.
- Deterministic.
- Single-threaded.
- Simulate timers.
- Simulate network socket (supply your own hooks).
- Detects deadlock (when all tasks are pending).

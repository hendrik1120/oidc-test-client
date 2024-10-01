OIDC Test Client
=============================

A very simple openid connect client for troubleshooting.

This is by no means intended as reference implementation.

In fact this is my first Go project.

## Application Setup

### Docker compose:

```yml
services:
  oidc-test:
    image: ghcr.io/hendrik1120/oidc-test-client:latest
    ports:
      - '8080:8080'
```

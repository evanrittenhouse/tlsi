# Plan
- need a custom version of boringssl so that I can add patches that remove some of the verification functions 
        - supplying empty ECH configs is a good test
- only support UDP to start since we want to test bastion (can move to SslStream in the future)

similar to h3i:
1. CLI interface (can be done with AI)
        - would be cool to have some statistics in the CLI interface, such as upstream TTFB, certificate information (see `pls`), handshake success, etc.
2. application layer (library)
3. need to have a way to delay sending TLS messages (e.g. Actions)
        - reading is fine, since internal state doesn't matter - we should be able to control flushing individual messages though 

Actions
1. SendClientHello
2. Wait (time or for response, like h3i)


handshaker similarities:
1. Thin wrapper around boring - don't want to be opinionated at all (e.g., bytestrings over strings wherever possible)

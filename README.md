# Syncretism

Syncretism provides a secure way of synchronizing a local directory
with a remote one. Its code-base is small, reviewable and written
with extreme care.

## Usage

```shell
Usage:
  syncretism -s [options] [ip:port] [remote]
  syncretism -c [options] [ip:port] [remote] [local]

Options
  -c       Run as a client
  -s       Run as a server
  -k       Absolute path to the shared secret
  -v       Print version information

On the client side specify both the remote and local
directories. For example, syncing the remote directory
/home/cathedral to a local directory called backup-231021:

  $ syncretism -c [options] 1.1.1.1:9191 /home/cathedral backup-231021

On the server side specify the root directory for all
requests. The server will restrict clients from requesting
file paths outside of the given root directory. For example
serving /home/cathedral to all clients:

  $ syncretism -s [options] 1.1.1.1:9191 /home/cathedral
```

## Protocol

The protocol runs over TCP and establishes a secure channel
in the following way:

```
Client                                        Server

32-byte random value      ------>
  (client_random)         <------       32-byte random value
                                           (server_random)
                          <------       64-byte random token
                                              (s_token)

                    Derive key material

           random = server_random || client_random

           s_key, c_key, s_encap, c_encap =
                 KMAC256(shared_secret, "SYNCRETISM.KDF", 0x100 || random)

           s_key = server sending key
           c_key = client sending key

           s_encap = server length encryption key
           c_encap = client length encryption key

   proof-of-key       ------>   accept or deny proof-of-key
 CreateMsg(s_token)
```

```
CreateMsg(data):
    K = c_key if client else s_key
    K' = c_encap if client else s_encap

    nonce = c_nonce if client else s_nonce
    nonce = nonce + 1

    length = len(data) - 32-bit (network byte order)
    encrypted_length = Agelas_Encrypt(K', length)

    ct, tag = Agelas(K, nonce || data, aad=encrypted_length || nonce)
    msg = encrypted_length || ct || tag

    return msg
```

Once the secure channel is established the client begins by sending
its view of the local directory.

Once the client indicates it has sent all files, the server will
look at its view of its directory and send the client missing or
out-dated files.

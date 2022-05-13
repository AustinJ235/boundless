# <font color="red">This project is very early in developement.</font>

### Boundless

Boundless is yet another keyboard / mouse sharing project. It is mainly implemented for my personal needs, so there are other projects that may have a greater feature scope or are more suitable for your needs. My use case / project goals, I use a gaming VM with gpu passthrough that runs Windows on a Linux host. Currently it is designed as Windows being the server and Linux the client.

##### Getting started

- The server and the client both must know each other.
- Add each host to each other's allowed hosts via ``--allow-remote-host``
  - You can obtain the verifying key of each host via ``--verifying-key``
- Start the server via ``--server 0.0.0.0:1504``
- Start the client via ``--client SERVER_ADDR:1504``
- Switch input on the host running the server with ``Right Ctrl``

##### Usage
```
--client CONNECT_SOCKET_ADDR [--enable-audio]
--server LISTEN_SOCKET_ADDR [--enable-audio]
--verifying-key
  Prints verifying key of this host.
--identifier
  Prints the identifier of this host.
--allowed-remote-hosts
  Prints list of remote hosts that are allowed.
--allow-remote-host VERIFYING_KEY
  Add remote host to the allowed hosts.
--remove-remote-host-by-key VERIFYING_KEY
  Remove remote host from allowed hosts.
--remove-remote-host-by-iden IDENTIFIER
  Remove remote host from allowed hosts.
```

##### Why is Windows the Server?
- More robust in capturing input. UInput can be flacky when it come to capturing input. Causing keys to remained pressed for example.
- Some games simply don't work with virtual inputs or ban you for using them.

##### What are some future goals?
- Messaging through VirtIO.
- Encryption while using network.
- Audio sharing.
- Clipboard sharing.

##### What are some other cool projects?
- [rkvm](https://github.com/htrefil/rkvm)
    - Similar project to this. 
    - Server/Client is the other way around from this project.
- [Synergy](https://symless.com/synergy)
    - Linux only supports Xorg
- [Barrier](https://github.com/debauchee/barrier)
    - Synergy alternative
    - Linux only supports Xorg
- [Waynergy](https://github.com/r-c-f/waynergy)
    - Synergy/Barrier client only
    - Supports Wayland!
    - Early in development.

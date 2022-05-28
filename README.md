# <font color="red">This project is very early in developement.</font>

### Boundless

Boundless is yet another keyboard / mouse sharing project. It is mainly implemented for my personal needs, so there are other projects that may have a greater feature scope or are more suitable for your needs. My use case / project goals, I use a gaming VM with gpu passthrough that runs Windows on a Linux host. Currently it is designed as Windows being the server and Linux the client.

##### Getting started

- The server and the client both must know each other.
- On each host run the following commands.
  - ``--generate-keys``
    - This will genenerate the private/public keys on this system.
  - ``--public-key``
    - This will print the public key of this system.
  - ``--trust PUBLIC_KEY``
    - ``PUBLIC_KEY`` is the output of ``--public-key`` of the other system.
- Start the server via ``--server 0.0.0.0:1504``
- Start the client via ``--client SERVER_ADDR:1504``
- Switch input on the host running the server with ``Right Ctrl``

##### Why is Windows the Server?
- More robust in capturing input. UInput can be flacky when it come to capturing input. Causing keys to remained pressed for example.
- Some games simply don't work with virtual inputs or ban you for using them.

##### What are some future goals?
- Audio sharing
  - Rought support currently with `--enable-audio`
  - Pulseaudio must support 88200 hz
  - Windows must be set at 88200 hz.
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

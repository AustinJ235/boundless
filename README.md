# <font color="red">This project is very early in developement.</font>

### Boundless

Boundless is yet another keyboard / mouse sharing project. It is mainly implemented for my personal needs, so there are other projects that may have a greater feature scope or are more suitable for your needs. My use case / project goals, I use a gaming VM with gpu passthrough that runs Windows on a Linux host. Currently it is designed as Windows being the server and Linux the client.

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

Virtual Private Network
=======================

Description
-----------
VPN is used for when one communication channel is blocked by something like firewall, it can still send data to the other end by transferring data through another channel. And, in this VPN project, the original channel was TCP and it was blocked. I used UDP Tunnel to transfer data.

There are two processes in this VPN. 
* The parent process is responsible for TCP/SSL connection:
  * Authentication between server and client.
  * Exchanging the key and Initial Vector(IV) between server and client.
  * Updating the session key for UDP Tunnel/
  * Control the UDP Tunnel. Start or terminating the VPN tunnel,
* The child process is responsible for UDP Tunnel, which is the real VPN channel for the communication. The UDP Tunnel is secure through encryption and MAC with help of tools from OpenSSL.
* Child process receives commands from parent process through pipe.

Main Jobs
---------
* Designed a mechanism that when one machine wants send message to the other machine, data will be delivered to user program through TUN interface, which wraps the TCP package into UDP package with encryption and MAC, then sending the package to the other end through UDP Tunnel, same as the reversion.
* Designed a parent process to build a TCP/SSL connection channel where client and server authenticate identity of each other by certificate of server and username and password of client respectively, through the functionality of OpenSSL
* Implemented exchanging of key and initial vector in TCP/SSL connection channel for encryption and MAC in the UDP Tunnel
* Designed a child process to build a UDP Tunnel where client and server could exchange information encrypted with AES128 algorithm and CBC mode for confidentiality and hashed with SHA256 for Integrity, using key and IV from parent process
* Developed a pipe for parent to send key and IV to child and control the communication in UDP Tunnel

# PowerWhois

--

Simple Whois Client in C-like C++98

--

### What is PowerWhois?

PowerWhois is similar to normal whois client, but it allows to specify outgoing IP adress where query will be send from.

### How to build it?

Just do:
> make

Code is optimized to be compiled on CentOS 6.x

To start it, just do
>./pwhois
or
> ./pwhois whois.internic.net photonhost.com
or
./pwhois whois.internic.net photonhost.com <outgoing ip>

### Disclamer

This tool is based on excelent example I found here:
http://www.binarytides.com/c-code-to-perform-ip-whois/

--

Distribution is GPL.

Nikolay Mihaylov

2016-11


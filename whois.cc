#include <sys/socket.h>	//socket
#include <netinet/in.h>	//sockaddr_in
#include <arpa/inet.h>	//getsockname
#include <netdb.h>	//hostent
#include <unistd.h>	//close

#include <cstring>	// strlen, strcpy

#include <string>
#include <iostream>

#define nullptr		NULL

const size_t SIZE_IP4	= 32;
const size_t SIZE_BUFFER	= 1024;

const int WHOIS_PORT	= 43;

namespace ERROR{
	const char *RESOLVE	= "ERROR:RESOLVE";
	const char *CONNECT	= "ERROR:CONNECT";
	const char *SEND	= "ERROR:SEND";
	const char *RECV	= "ERROR:RECV";
}

static std::string whois_query(const char *ip, int port, const char *domain, const char *bind_ip = nullptr);
static int print_usage(const char *program);

int main(int argc , char *argv[]){
#if 0
	(void)print_usage;

	const char *server	= "whois.publicinterestregistry.net";
	const char *domain	= "e-nick.org";
	const char *bind_ip	= "0.0.0.0";
#else
	if (argc <= 2)
		return print_usage(argv[0]);

	const char *server	= argv[1];
	const char *domain	= argv[2];
	const char *bind_ip	= argc >= 3 ? argv[3] : nullptr;
#endif
	const std::string data = whois_query(server, WHOIS_PORT, domain, bind_ip);

	std::cout << data << '\n';
}

static const char *hostname_to_ip(const char *hostname, char *buffer);

static struct sockaddr_in prepareAddress(const char *ip){
	struct sockaddr_in addr;
	memset( &addr, 0, sizeof(addr) );

	addr.sin_family		= AF_INET;
	addr.sin_addr.s_addr	= inet_addr(ip);

	return addr;
}

static struct sockaddr_in prepareAddress(const char *ip, int const port){
	struct sockaddr_in addr = prepareAddress(ip);

	addr.sin_port		= htons(port);

	return addr;
}

static std::string whois_query(const char *server, int const port, const char *domain, const char *bind_ip){
	int sock = socket(AF_INET , SOCK_STREAM , IPPROTO_TCP);

	char ip[SIZE_IP4];

	if (! hostname_to_ip(server , ip) )
		return ERROR::RESOLVE;

	const struct sockaddr_in dest = prepareAddress(ip, port);

	if (bind_ip){
		const struct sockaddr_in localaddr = prepareAddress(bind_ip);

		bind(sock, (const struct sockaddr *) &localaddr, sizeof(localaddr));
	}

	if (connect(sock , (const struct sockaddr*) &dest , sizeof(dest) ) < 0)
		return ERROR::CONNECT;

	if (
		send(sock , domain, strlen(domain) , 0) < 0	||
		send(sock , "\r\n", 2 , 0) < 0
		){

		return ERROR::SEND;
	}

	std::string data;

	{
		char buffer[SIZE_BUFFER];

		while( ssize_t read_size = recv(sock, buffer, SIZE_BUFFER, 0) )
			if (read_size > 0)
				data.append(buffer, read_size);
	}

	close(sock);

	return data;
}


static const char *hostname_to_ip(const char *hostname, char *buffer){
	struct hostent *he = gethostbyname(hostname);

	if (! he )
		return nullptr;

	const struct in_addr **addr_list = (const struct in_addr **) he->h_addr_list;

	const struct in_addr *front = addr_list[0];

	if (front){
		strcpy(buffer, inet_ntoa(*front));

		return buffer;
	}

	return nullptr;
}


static int print_usage(const char *program){
	std::cout
		<< "Power whois v.0.2"							<< '\n'
		<< "Copyleft 2016-11-22, Nikolay Mihaylov"				<< '\n'
		<< "Based on: http://www.binarytides.com/c-code-to-perform-ip-whois/"	<< '\n'
		<< '\n'
		<< "Usage " << program << " [whois.server] [domain.tld] [[local_ip]]"	<< '\n'
		<< '\n';

	return 1;
}


#include <sys/socket.h>	//socket
#include <netinet/in.h>	//sockaddr_in
#include <arpa/inet.h>	//getsockname
#include <netdb.h>	//hostent
#include <unistd.h>	//close

#include <cstring>	// strlen, strcpy

#include <string>
#include <iostream>


constexpr size_t SIZE_IP4	= 32;
constexpr size_t SIZE_BUFFER	= 1024;

constexpr int WHOIS_PORT	= 43;

namespace ERROR{
	constexpr const char *RESOLVE	= "ERROR:RESOLVE";
	constexpr const char *CONNECT	= "ERROR:CONNECT";
	constexpr const char *SEND	= "ERROR:SEND";
}

static std::string whois_query(const char *ip, const char *domain, const char *bind_ip = nullptr);
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
	std::string data = whois_query(server, domain, bind_ip);

	std::cout << data << '\n';
}

static bool hostname_to_ip(const char *hostname, char *ip);

static std::string whois_query(const char *server, const char *domain, const char *bind_ip){
	int sock = socket(AF_INET , SOCK_STREAM , IPPROTO_TCP);

	struct sockaddr_in dest;
	memset( &dest , 0 , sizeof(dest) );
	dest.sin_family = AF_INET;

	char ip[SIZE_IP4];

	if(hostname_to_ip(server , ip) == false){
		return ERROR::RESOLVE;
	}

	dest.sin_addr.s_addr = inet_addr( ip );
	dest.sin_port = htons(WHOIS_PORT);

	if(connect(sock , (const struct sockaddr*) &dest , sizeof(dest) ) < 0){
		return ERROR::CONNECT;
	}

	if (bind_ip){
		struct sockaddr_in localaddr;

		localaddr.sin_family = AF_INET;
		localaddr.sin_addr.s_addr = inet_addr(bind_ip);
		localaddr.sin_port = 0;
		bind(sock, (struct sockaddr *) &localaddr, sizeof(localaddr));
	}

	if (
		send(sock , domain, strlen(domain) , 0) < 0	||
		send(sock , "\r\n", 2 , 0) < 0
		){

		return ERROR::SEND;
	}

	std::string data;

	{
		char buffer[SIZE_BUFFER];

		ssize_t read_size;
		while( (read_size = recv(sock , buffer , SIZE_BUFFER , 0) ) )
			data.append(buffer, read_size);
	}

	close(sock);

	return data;
}


static bool hostname_to_ip(const char *hostname, char *ip){
	struct hostent *he = gethostbyname(hostname);

	if ( he == nullptr)
		return false;

	struct in_addr **addr_list = (struct in_addr **) he->h_addr_list;

	const struct in_addr *front = addr_list[0];

	if (front){
		strcpy(ip, inet_ntoa(*front));

		return true;
	}

	return false;
}


static int print_usage(const char *program){
	std::cout
		<< "Power whois v.0.1"							<< '\n'
		<< "Copyleft 2016-11-22, Nikolay Mihaylov"				<< '\n'
		<< "Based on: http://www.binarytides.com/c-code-to-perform-ip-whois/"	<< '\n'
		<< '\n'
		<< "Usage " << program << " whois.server domain.tld [local_ip]"		<< '\n'
		<< '\n';

	return 1;
}


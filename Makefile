#MYCC		= clang++
MYCC		= g++

CF_OPTIM	= -O2
CF_WARN		= -Wall -Wdeprecated -Wconversion

CF_MISC		=

CF_ALL		= \
			$(CF_OPTIM)	\
			$(CF_WARN)	\
			$(CF_MISC)

CXX		= $(MYCC) $(CF_ALL)

# ======================================================

LD_ALL		=
LL_ALL		= -lstdc++

LINK		= $(MYCC) $(LD_ALL) -o $@ $^ $(LL_ALL)

pwhois: whois.o
	$(LINK)

whois.o: whois.cc
	$(CXX) -c whois.cc

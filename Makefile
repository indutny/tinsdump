CFLAGS ?=
CFLAGS += -g -O0

LDFLAGS ?=
LDFLAGS += -ltins

OBJ =
OBJ += main.o

%.o: %.cc
	$(CXX) $(CFLAGS) -c $< -o $@

tinsdump: $(OBJ)
	$(CXX) $(LDFLAGS) $< -o $@

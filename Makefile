.PHONY:all clean run

CC := gcc
OBJS := server.o 
BIN := $(firstword $(OBJS:%.o=%))
CFLAGS := -g -Wall -Wextra -Wno-unused-parameter -Wno-unused-variable -MMD
CFLAGS += -DNDEBUG
deps := $(OBJS:%.o=%.d)

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $<

clean:
	$(RM) $(deps) $(OBJS) $(BIN)

run:
	@if [ ! -f ./$(BIN) ]; then \
		echo "'make' first!"; \
	else \
		echo "For local test please visit 127.0.0.1:8888 in your browser!"; \
	    ./$(BIN); \
	fi

-include $(deps)
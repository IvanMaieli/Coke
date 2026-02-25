CC = gcc
CFLAGS  = -Wall -Wextra -std=c11 -O3 -Iinclude -D_POSIX_C_SOURCE=200809L -D_GNU_SOURCE
LDFLAGS = -lpthread -lncurses

SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin

TARGET = $(BIN_DIR)/coca
SRCS = $(wildcard $(SRC_DIR)/*.c)
OBJS = $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRCS))

all: directories $(TARGET)

directories:
	@mkdir -p $(OBJ_DIR) $(BIN_DIR)

$(TARGET): $(OBJS)
	@echo "🔗 Linking $(TARGET)..."
	@$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@echo "🔨 Compiling $<..."
	@$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)

.PHONY: all directories clean

# Compiler and Flags
CC = gcc
CFLAGS = -Wall -Wextra -Wshadow -std=c11 -O3 -Iinclude
LDFLAGS = 

# Folder Structure
SRC_DIR = src
INC_DIR = include
OBJ_DIR = obj
BIN_DIR = bin

# Target Binary Name
TARGET = $(BIN_DIR)/Coke

# Discovery: Trova tutti i file .c nella cartella src
SRCS = $(wildcard $(SRC_DIR)/*.c)
# Trasforma i nomi dei .c in nomi di file .o nella cartella obj
OBJS = $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRCS))

# --- RULES ---

# Regola principale: compila tutto
all: setup $(TARGET)

# Crea le cartelle necessarie se non esistono
setup:
	@mkdir -p $(OBJ_DIR) $(BIN_DIR)

# Linker: Assembla gli oggetti nel binario finale
$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS)
	@echo "Compilation successful: $(TARGET)"

# Compiler: Trasforma ogni .c in un .o
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# Pulizia: Rimuove i file compilati
clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)
	@echo "Project cleaned"

# Debug mode: Compila con simboli per gdb/valgrind
debug: CFLAGS = -Wall -Wextra -std=c11 -g -Iinclude
debug: clean all

# Compiler and Flags
CC = gcc
CFLAGS = -Wall -Wextra -g -O2 -Iinclude -MMD

# Directories
SRCDIR = src
INCDIR = include
OBJDIR = obj
BINDIR = bin

# Source, Object, and Dependency files
SOURCES = $(wildcard $(SRCDIR)/*.c)
OBJS = $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(SOURCES))
DEPS = $(OBJS:.o=.d)

# Output binary file
TARGET = $(BINDIR)/program

# Default target
all: dir $(TARGET)

# Create necessary directories for obj and bin
dir:
	@mkdir -p $(OBJDIR) $(BINDIR)

# Rule to build the target
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $@

# Rule to build object files and track dependencies
$(OBJDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# Include the dependency files
-include $(DEPS)

# Clean build (removes objects, dependencies, and binaries)
clean:
	rm -rf $(OBJDIR) $(BINDIR)

# Rebuild target (clean + build)
rebuild: clean all

# Run the compiled program
run: $(TARGET)
	./$(TARGET)

# Phony targets (so that they don't conflict with file names)
.PHONY: all clean rebuild run
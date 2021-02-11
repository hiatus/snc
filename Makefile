TARGET := snc
SRCDIR := src
OBJDIR := obj
INCDIR := $(SRCDIR)/include
OBJALL := $(addprefix $(OBJDIR)/, $(addsuffix .o, crc32 sha3 aes init io net main))

CFLAGS := -std=gnu99 -Wall -Wextra -I$(INCDIR)

$(TARGET): $(OBJALL)
	@echo [$(CC)] -lpthread -lutil $@
	@$(CC) -o $@ $(OBJALL) -lpthread -lutil

$(OBJDIR):
	@mkdir $(OBJDIR)

$(OBJDIR)/main.o: $(SRCDIR)/main.c $(addprefix $(INCDIR)/, snc.h net.h io.h)
	@echo [$(CC)] -O2 $@
	@$(CC) $(CFLAGS) -Ofast -c -o $@ $<

$(OBJDIR)/net.o: $(SRCDIR)/net.c $(addprefix $(INCDIR)/, net.h snc.h init.h aes.h sha3.h crc32.h)
	@echo [$(CC)] -O2 $@
	@$(CC) $(CFLAGS) -O2 -c -o $@ $<

$(OBJDIR)/io.o: $(SRCDIR)/io.c $(addprefix $(INCDIR)/, io.h net.h snc.h)
	@echo [$(CC)] -O2 $@
	@$(CC) $(CFLAGS) -O2 -c -o $@ $<

$(OBJDIR)/init.o: $(SRCDIR)/init.c $(addprefix $(INCDIR)/, init.h aes.h sha3.h)
	@echo [$(CC)] -O2 $@
	@$(CC) $(CFLAGS) -O2 -c -o $@ $<

$(OBJDIR)/aes.o: $(SRCDIR)/aes.c $(INCDIR)/aes.h
	@echo [$(CC)] -Ofast $@
	@$(CC) $(CFLAGS) -Ofast -c -o $@ $<

$(OBJDIR)/sha3.o: $(SRCDIR)/sha3.c $(INCDIR)/sha3.h
	@echo [$(CC)] -Ofast $@
	@$(CC) $(CFLAGS) -Ofast -c -o $@ $<

$(OBJDIR)/crc32.o: $(SRCDIR)/crc32.c $(INCDIR)/crc32.h
	@echo [$(CC)] -Ofast $@
	@$(CC) $(CFLAGS) -Ofast -c -o $@ $<

$(OBJALL): | $(OBJDIR)

clean:
	@echo [rm] $(TARGET) $(OBJDIR)
	@rm -rf $(TARGET) $(OBJDIR)

.PHONY: clean

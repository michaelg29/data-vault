
EXE=dv
COMP_MODE=DV_CMP_DEBUG

#########################
##### Configuration #####
#########################

# programs
CC               =gcc
TARGET_ARCH      ?= linux64
ifneq (,$(strip $(TARGET_ARCH)))
  ARCH_SUFFIX      ?= -$(TARGET_ARCH)
endif

# compiler flags
#CFLAGS ?= -g3
#IFLAGS += -I./include
LFLAGS  = -lm

ifneq (,$(COMP_MODE))
  DEFINE_FLAGS = -D $(COMP_MODE)
endif

####################
##### OS setup #####
####################
SRCROOT=../src

ifeq ($(OS),Windows_NT)
    RM = del /F /Q /q 
		CP = copy
    RMDIR = -RMDIR /S /Q
    MKDIR = -mkdir
    ERRIGNORE = 2>NUL || true
    SEP=\\
		VPATH := $(subst $(space),:,$(shell dir /s /a:d /b ..\src))
		SRCS  := $(shell dir /s /b ..\src\*.c)
		DEPS  := $(shell dir /s /b ..\src\*.h)
		
		EXE_PATH=$(EXE).exe
		RUN_EXE=$(EXE_PATH)
else
    RM = rm -rf 
		CP = cp
    RMDIR = rm -rf 
    MKDIR = mkdir -p
    ERRIGNORE = 2>/dev/null
    SEP=/
		VPATH := $(subst $(space),:,$(shell find ../src -type d))
		SRCS  := $(shell find ../src -type f -iregex [.]*\/[^.]*\.c)
		DEPS  := $(shell find ../src -type f -iregex [.]*\/[^.]*\.h)
		
		EXE_PATH=$(EXE)
		RUN_EXE=./$(EXE_PATH)
endif

########################
##### Source setup #####
########################

# file lists
OBJS := $(patsubst %.c,%.o,$(SRCS))

###################
##### Targets #####
###################

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS) $(IFLAGS) $(DEFINE_FLAGS)

$(EXE): $(OBJS)
	$(CC) -o $@ $^ $(CFLAGS) $(LFLAGS) $(DEFINE_FLAGS)

run: $(EXE_PATH)
	$(RUN_EXE)
	
release: $(EXE)
	$(CP) $(EXE_PATH) ../bin/$(EXE_PATH)

.PHONY: clean

clean:
	$(RM) $(OBJS) $(EXE_PATH) *.vcd

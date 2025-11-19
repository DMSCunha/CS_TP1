######## App Settings ########

APP_NAME   := ewallet

APP_DIR    := application
APP_SRCDIR := $(APP_DIR)/src
APP_INCDIR := $(APP_DIR)/inc
APP_OBJDIR := $(APP_DIR)/obj
APP_BINDIR := $(APP_DIR)/bin

App_C_Files := $(wildcard $(APP_SRCDIR)/*.c)

App_C_Objects := $(App_C_Files:$(APP_SRCDIR)/%.c=$(APP_OBJDIR)/%.o)

App_Include_Paths := -I$(APP_INCDIR) -I$(SGX_SDK)/include

App_C_Flags := -fPIC -Wno-attributes $(App_Include_Paths)

# Debug configuration mode - Macro DEBUG enabled
App_C_Flags += -DDEBUG -UNDEBUG -UEDEBUG

App_Cpp_Flags := $(App_C_Flags)

App_Link_Flags := -lm

.PHONY: all target run
all:
	@$(MAKE) target

target: $(APP_BINDIR)/$(APP_NAME)

run: all
	@cd $(APP_BINDIR) && ./$(APP_NAME)
	@echo "RUN  =>  $(APP_NAME) [$(SGX_MODE)|$(SGX_ARCH), OK]"

######## App Objects ########

$(APP_OBJDIR)/%.o: $(APP_SRCDIR)/%.c
	@$(CC) $(SGX_COMMON_CFLAGS) $(App_C_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(APP_BINDIR)/$(APP_NAME): $(App_C_Objects)
	@$(CC) $^ -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"

.PHONY: clean
clean:
	@rm -f $(APP_BINDIR)/$(APP_NAME) $(App_C_Objects)
	@echo "Cleanup complete!"

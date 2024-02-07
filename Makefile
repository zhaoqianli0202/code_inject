CURRENT_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
include  ${SRC_BUILD_DIR}/core/Makefile
ifeq (${BUILD_OUTPUT_PATH},)
export BUILD_OUTPUT_PATH=$(shell pwd)
endif

INJECTOR = ${BUILD_OUTPUT_PATH}/code_injector
LIBCODE_INJECT = ${BUILD_OUTPUT_PATH}/libcode_inject.so
INCS += -I${CURRENT_DIR}/includes/

.PHONY:all clean
all: $(LIBCODE_INJECT) $(INJECTOR)

LIBINJECTSRC = $(wildcard $(CURRENT_DIR)/src/arm64_inlinehook.cpp)
LIBINJECTOBJS := $(LIBINJECTSRC:$(CURRENT_DIR)%.cpp=$(BUILD_OUTPUT_PATH)/%.o)
LIBS1 = $(LIBS)
CXXFLAGS += -g -O3

$(BUILD_OUTPUT_PATH)/%.o: $(CURRENT_DIR)/%.cpp
	$(CXX) $(CFLAGS_DYNAMIC) $(CXXFLAGS) $(INCS) -c $^ -o $@

$(LIBCODE_INJECT): $(LIBINJECTOBJS)
	@mkdir -p $(abspath $(dir $@))
	$(CXX) $(CFLAGS_DYNAMIC) $^ $(LDFLAGS) $(LIBS1) -o $@

######
HOTPATCHSRC = $(wildcard $(CURRENT_DIR)/src/code_injector.cpp $(CURRENT_DIR)/src/inject_info.cpp $(CURRENT_DIR)/src/injector.cpp $(CURRENT_DIR)/src/inject_parser.cpp $(CURRENT_DIR)/src/subcmd_control.cpp)
PATCHOBJS := $(HOTPATCHSRC:$(CURRENT_DIR)%.cpp=$(BUILD_OUTPUT_PATH)/%.o)
LIBS2 = $(LIBS) -lalog -lcode_inject -lelf -ldl -ljsoncpp
LDFLAGS += -L${BUILD_OUTPUT_PATH}/
INCS += -I${TARGET_THIRD_PARTY_DIR}/usr/include

$(PATCHOBJS): ${BUILD_OUTPUT_PATH}/%.o:$(CURRENT_DIR)/%.cpp
	$(CXX) $(CXXFLAGS) $(INCS) -c $^ -o $@

$(INJECTOR): $(PATCHOBJS) $(LIBCODE_INJECT)
	@mkdir -p $(abspath $(dir $@))
	$(CXX) -o $@ $(CXXFLAGS) $(LDFLAGS) $(INCS) $(PATCHOBJS) $(LIBS2)

clean:
	rm -rf $(INJECTOR) $(PATCHOBJS)
	rm -rf $(LIBCODE_INJECT) $(LIBINJECTOBJS)

CURRENT_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
include  ${SRC_BUILD_DIR}/core/Makefile
ifeq (${BUILD_OUTPUT_PATH},)
export BUILD_OUTPUT_PATH=$(shell pwd)
endif

LIBPERF_PROFILE = ${BUILD_OUTPUT_PATH}/libperf_profile.so
PERF_PARSER = ${BUILD_OUTPUT_PATH}/perf_parser.elf
INCS += -I$(CURRENT_DIR)/ -I$(CURRENT_DIR)/../includes/

.PHONY:all clean
all: $(LIBPERF_PROFILE) $(PERF_PARSER)

LIBPERFSRC = $(wildcard $(CURRENT_DIR)/perf_profile.cpp)
LIBPERFOBJS := $(patsubst $(CURRENT_DIR)/%, $(BUILD_OUTPUT_PATH)/%, $(patsubst %.S, %.o, $(patsubst %.cpp, %.o, $(LIBPERFSRC))))
LIBS1 = $(LIBS) -ljsoncpp -lalog
CXXFLAGS += -g -O3

$(BUILD_OUTPUT_PATH)/%.o: $(CURRENT_DIR)/%.cpp
	$(CXX) $(CFLAGS_DYNAMIC) $(CXXFLAGS) $(INCS) -c $^ -o $@

$(LIBPERF_PROFILE): $(LIBPERFOBJS)
	@mkdir -p $(abspath $(dir $@))
	$(CXX) $(CFLAGS_DYNAMIC) $^ $(LDFLAGS) $(LIBS1) -o $@

$(PERF_PARSER): $(CURRENT_DIR)/parse_profile_file.cpp
	$(CXX) -o $@ $(CXXFLAGS) $(INCS) $(LDFLAGS) $(CURRENT_DIR)/parse_profile_file.cpp $(LIBS1)

clean:
	rm -rf $(LIBPERFOBJS) $(LIBPERF_PROFILE) $(PERF_PARSER)

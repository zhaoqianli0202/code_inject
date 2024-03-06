CURRENT_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
include  ${SRC_BUILD_DIR}/core/Makefile
ifeq (${BUILD_OUTPUT_PATH},)
export BUILD_OUTPUT_PATH=$(shell pwd)
endif

LIBHOOK_HELPER = ${BUILD_OUTPUT_PATH}/libhook_helper.so
INCS += -I$(CURRENT_DIR)/ -I$(CURRENT_DIR)/../includes/

.PHONY:all clean
all: $(LIBHOOK_HELPER)

LIBHELPERSRC = $(wildcard $(CURRENT_DIR)/hooker.S $(CURRENT_DIR)/hook_helper.cpp)
LIBHELPEROBJS := $(patsubst $(CURRENT_DIR)/%, $(BUILD_OUTPUT_PATH)/%, $(patsubst %.S, %.o, $(patsubst %.cpp, %.o, $(LIBHELPERSRC))))
LIBS1 = $(LIBS) -lpthread -lalog
CXXFLAGS += -g -O3

$(BUILD_OUTPUT_PATH)/%.o: $(CURRENT_DIR)/%.cpp
	$(CXX) $(CFLAGS_DYNAMIC) $(CXXFLAGS) $(INCS) -c $^ -o $@

$(LIBHOOK_HELPER): $(LIBHELPEROBJS)
	@mkdir -p $(abspath $(dir $@))
	$(CXX) $(CFLAGS_DYNAMIC) $^ $(LDFLAGS) $(LIBS1) -o $@

clean:
	rm -rf $(LIBHELPEROBJS) $(LIBHOOK_HELPER)

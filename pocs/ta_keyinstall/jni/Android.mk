LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := poc
LOCAL_CFLAGS += -std=c99 -ggdb # -pthread
LOCAL_SRC_FILES := poc.c
LOCAL_C_INCLUDES := $(LOCAL_PATH)/../../include

include $(BUILD_EXECUTABLE)


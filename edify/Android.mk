#
# Copyright (C) 2014 MediaTek Inc.
# Modification based on code covered by the mentioned copyright
# and/or permission notice(s).
#
# Copyright 2009 The Android Open Source Project

LOCAL_PATH := $(call my-dir)

edify_src_files := \
	lexer.l \
	parser.y \
	expr.c

# "-x c" forces the lex/yacc files to be compiled as c;
# the build system otherwise forces them to be c++.
edify_cflags := -x c

#
# Build the host-side command line tool
#
include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
		$(edify_src_files) \
		main.c

LOCAL_CFLAGS := $(edify_cflags) -g -O0
LOCAL_MODULE := edify
LOCAL_YACCFLAGS := -v
LOCAL_CFLAGS += -Wno-unused-parameter

include $(BUILD_HOST_EXECUTABLE)

#
# Build the device-side library
#
include $(CLEAR_VARS)

LOCAL_SRC_FILES := $(edify_src_files)

LOCAL_CFLAGS := $(edify_cflags)
LOCAL_CFLAGS += -Wno-unused-parameter
LOCAL_MODULE := libedify
LOCAL_MULTILIB := both

include $(BUILD_STATIC_LIBRARY)

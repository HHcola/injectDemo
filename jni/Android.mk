# Copyright (C) 2009 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE    := inject
LOCAL_SRC_FILES	:= inject.c 
LOCAL_LDLIBS := -L$(SYSROOT)/usr/lib -llog 

#LOCAL_FORCE_STATIC_EXECUTABLE := true 

#include $(BUILD_SHARED_LIBRARY)
include $(BUILD_EXECUTABLE)


#编译多个so文件：Android.mk中可以定义多个编译模块，每个编译模块都是以include $(CLEAR_VARS)开始，以include $(BUILD_XXX)结束
include $(CLEAR_VARS)

LOCAL_MODULE    := hello
LOCAL_SRC_FILES	:= hello.c 
LOCAL_LDLIBS := -L$(SYSROOT)/usr/lib -llog 

include $(BUILD_SHARED_LIBRARY)
#include $(BUILD_EXECUTABLE)

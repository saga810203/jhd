################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../src/jhd_conf.c \
../src/jhd_connection.c \
../src/jhd_core.c \
../src/jhd_event.c \
../src/jhd_log.c \
../src/jhd_pool.c \
../src/jhd_process.c \
../src/jhd_rbtree.c \
../src/jhd_shm.c \
../src/jhd_string.c \
../src/jhd_time.c \
../src/jhttpd.c 

OBJS += \
./src/jhd_conf.o \
./src/jhd_connection.o \
./src/jhd_core.o \
./src/jhd_event.o \
./src/jhd_log.o \
./src/jhd_pool.o \
./src/jhd_process.o \
./src/jhd_rbtree.o \
./src/jhd_shm.o \
./src/jhd_string.o \
./src/jhd_time.o \
./src/jhttpd.o 

C_DEPS += \
./src/jhd_conf.d \
./src/jhd_connection.d \
./src/jhd_core.d \
./src/jhd_event.d \
./src/jhd_log.d \
./src/jhd_pool.d \
./src/jhd_process.d \
./src/jhd_rbtree.d \
./src/jhd_shm.d \
./src/jhd_string.d \
./src/jhd_time.d \
./src/jhttpd.d 


# Each subdirectory must supply rules for building sources it contributes
src/%.o: ../src/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -I"/eclipse/workspace3/jhttpd/include" -O0 -c -pipe  -O -W -Wall -Wpointer-arith -Wno-unused-parameter -Werror -g -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '



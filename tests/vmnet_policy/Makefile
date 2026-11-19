# Portable tests for the solo5-vmnet egress policy. No macOS required.
#
#   make -C tests/vmnet_policy check
CC ?= cc
CFLAGS := -std=c11 -O2 -g -Wall -Wextra -Werror $(CFLAGS)
CPPFLAGS += -I../../tenders/vmnet

.PHONY: all check clean
all: policy_test

policy_test: policy_test.c ../../tenders/vmnet/policy.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

check: policy_test
	./policy_test

clean:
	$(RM) policy_test

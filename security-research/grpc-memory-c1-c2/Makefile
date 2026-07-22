# Build + run the C1/C2 memory-safety PoCs.
#
#   make asan   # detection: real new[], ASan aborts with heap-buffer-overflow
#   make rce    # exploitation: overflow -> control-flow hijack (deterministic layout)
#   make        # both
#
# ASan builds prove the overflow is real against the actual allocator.
# RCE builds run -no-pie so hijacked addresses are deterministic and printable.
CXX      ?= g++
ASANFLAGS = -g -O0 -fsanitize=address
RCEFLAGS  = -g -O0 -no-pie

.PHONY: all asan rce clean
all: asan rce

asan:
	@echo "==================== C1 - ASan detection ===================="
	$(CXX) $(ASANFLAGS) poc_c1_asan.cpp -o c1_asan
	-ASAN_OPTIONS=abort_on_error=0 ./c1_asan
	@echo "\n==================== C2 - ASan detection ===================="
	$(CXX) $(ASANFLAGS) poc_c2_asan.cpp -o c2_asan
	-ASAN_OPTIONS=abort_on_error=0 ./c2_asan

rce:
	@echo "==================== C1 - control-flow hijack ===================="
	$(CXX) $(RCEFLAGS) poc_c1_rce.cpp -o c1_rce
	./c1_rce
	@echo "\n==================== C2 - partial-overwrite hijack ===================="
	$(CXX) $(RCEFLAGS) poc_c2_rce.cpp -o c2_rce
	./c2_rce

clean:
	rm -f c1_asan c2_asan c1_rce c2_rce

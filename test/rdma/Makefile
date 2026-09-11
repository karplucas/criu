# INTERNAL VALIDATION ONLY -- drop before upstream PR.

CFLAGS  ?= -Wall -Wextra -O2 -g

all: uverbs_ctx_holder vfmig_barrier_peer rxe_image_test

uverbs_ctx_holder: LDLIBS := -libverbs
uverbs_ctx_holder: uverbs_ctx_holder.c

# Standalone barrier peer stand-in (wire-only; no libibverbs).
vfmig_barrier_peer: vfmig_barrier_peer.c

rxe_image_test: CPPFLAGS += -iquote../../criu/include -iquote../../plugins/rdma/rxe
rxe_image_test: rxe_image_test.c ../../plugins/rdma/rxe/rxe_image.c

clean:
	$(RM) uverbs_ctx_holder vfmig_barrier_peer rxe_image_test

.PHONY: all clean

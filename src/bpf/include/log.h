#ifndef BPFCONTAIN_LOG_H
#define BPFCONTAIN_LOG_H

#include "bpf.h"
#include "maps.h"
#include "shared/log.h"

BPF_RINGBUF(__bpfcontain_log, 16, 0) __weak;

#define LOG(___level, fmt, args...) \
({ \
	int ret = 0; \
	static const char ___fmt[] = fmt; \
	BPFContainLog *___log = bpf_ringbuf_reserve(&__bpfcontain_log, sizeof(BPFContainLog), 0); \
	if (!___log) { \
		ret = -1; \
	} else { \
		___log->level = ___level; \
		ret = BPF_SNPRINTF(___log->msg, __BPFCONTAIN_LOG_MSG_SIZE, fmt, args); \
		if (ret > 0) {\
			bpf_ringbuf_submit(___log, 0); \
		} else { \
			bpf_ringbuf_discard(___log, 0); \
		 }\
	} \
	ret; \
})

#endif /* ifndef BPFCONTAIN_LOG_H */

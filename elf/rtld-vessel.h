#ifndef _RTLD_VESSEL_H
#define _RTLD_VESSEL_H

#define VESSEL_ALIGN_SIZE  4096
#define VESSEL_UPPER_ALIGN(size)   (((size) + VESSEL_ALIGN_SIZE - 1) & (~(VESSEL_ALIGN_SIZE - 1)))


typedef void*(*v_aligned_alloc_t)(size_t alignment, size_t size);
typedef void*(*v_malloc_t)(size_t size);
typedef void*(*v_calloc_t)(size_t nmemb, size_t size);
typedef void*(*v_realloc_t)(void *ptr, size_t n);
typedef void(*v_free_t)(void*);

struct minimal_ops {
    void* aligned_alloc;
    void* malloc;
    void* calloc;
    void* free;
    void* realloc;
};
typedef struct minimal_ops minimal_ops_t;

struct minimal_ops_map {
    minimal_ops_t *map[8192];
};
typedef struct minimal_ops_map minimal_ops_map_t;

extern const void* vessel_minimal_ops_map_ptr;

static __always_inline uint32_t _rdpid_safe(void)
{
	uint32_t a, d, c;
	asm volatile("rdtscp" : "=a" (a), "=d" (d), "=c" (c));
	return c;
};

static __always_inline minimal_ops_t* vessel_get_ops(void) {
    return ((minimal_ops_map_t*) vessel_minimal_ops_map_ptr)->map[_rdpid_safe()];
};
#endif //_RTLD_VESSEL_H
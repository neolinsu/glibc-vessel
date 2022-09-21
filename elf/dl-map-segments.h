/* Map in a shared object's segments.  Generic version.
   Copyright (C) 1995-2021 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <https://www.gnu.org/licenses/>.  */

#include <dl-load.h>

/* This implementation assumes (as does the corresponding implementation
   of _dl_unmap_segments, in dl-unmap-segments.h) that shared objects
   are always laid out with all segments contiguous (or with gaps
   between them small enough that it's preferable to reserve all whole
   pages inside the gaps with PROT_NONE mappings rather than permitting
   other use of those parts of the address space).  */

typedef void*(*malloc_t)(size_t alignment, size_t size);
void** vessel_malloc_ptr = (void**) 0x8d042000;

static __always_inline uint32_t _rdpid_safe(void)
{
	uint32_t a, d, c;
	asm volatile("rdtscp" : "=a" (a), "=d" (d), "=c" (c));
	return c;
};

#define VESSEL_ALIGN_SIZE  4096
#define VESSEL_UPPER_ALIGN(size)   (((size) + VESSEL_ALIGN_SIZE - 1) & (~(VESSEL_ALIGN_SIZE - 1)))

static __always_inline const char *
_dl_map_segments (struct link_map *l, int fd,
                  const ElfW(Ehdr) *header, int type,
                  const struct loadcmd loadcmds[], size_t nloadcmds,
                  const size_t maplength, bool has_holes,
                  struct link_map *loader)
{
  const struct loadcmd *c = loadcmds;
  int ret;
  if (__glibc_likely (type == ET_DYN))
    {
      /* This is a position-independent shared object.  We can let the
         kernel map it anywhere it likes, but we must have space for all
         the segments in their specified positions relative to the first.
         So we map the first segment without MAP_FIXED, but with its
         extent increased to cover all the segments.  Then we remove
         access from excess portion, and there is known sufficient space
         there to remap from the later segments.

         As a refinement, sometimes we have an address that we would
         prefer to map such objects at; but this is only a preference,
         the OS can do whatever it likes. */
      ElfW(Addr) mappref
        = (ELF_PREFERRED_ADDRESS (loader, maplength,
                                  c->mapstart & GLRO(dl_use_load_bias))
           - MAP_BASE_ADDR (l));

      /* Remember which part of the address space this object uses.  */
      void * res = __mmap ((void*)mappref, maplength, PROT_READ, MAP_COPY|MAP_FILE, fd, c->mapoff);
      
      malloc_t my_malloc = (malloc_t) *(vessel_malloc_ptr + _rdpid_safe());
      
      void * dest = my_malloc(VESSEL_ALIGN_SIZE, VESSEL_UPPER_ALIGN(maplength));
      _dl_debug_printf("dest: %lx\n", (u_int64_t)dest);
      _dl_debug_printf("dest to: %lx\n", (u_int64_t)dest+VESSEL_UPPER_ALIGN(maplength));
//      _dl_debug_printf("diff: %ld\n", loadcmds[nloadcmds - 1].mapend - c->mapstart);
//      _dl_debug_printf("maplength: %ld\n", maplength);
      memcpy(dest, res, maplength);
      
      if(__mprotect(dest, VESSEL_UPPER_ALIGN(maplength), c->prot)) {
        _dl_debug_printf("Fail to mprotect for %d\n", errno);
      }

      l->l_map_start = (ElfW(Addr)) dest;
      if (__glibc_unlikely ((void *) l->l_map_start == NULL)) {
        _dl_debug_printf("Check\n");
        return DL_MAP_SEGMENTS_ERROR_MAP_SEGMENT;
      }

      l->l_map_end = l->l_map_start + maplength;
      l->l_addr = l->l_map_start - c->mapstart;

      if (has_holes)
        {
          /* Change protection on the excess portion to disallow all access;
             the portions we do not remap later will be inaccessible as if
             unallocated.  Then jump into the normal segment-mapping loop to
             handle the portion of the segment past the end of the file
             mapping.  */
          if (__glibc_unlikely
              (__mprotect ((caddr_t) (l->l_addr + c->mapend),
                           loadcmds[nloadcmds - 1].mapstart - c->mapend,
                           PROT_NONE) < 0)) {
                              _dl_debug_printf("Check\n");
                              return DL_MAP_SEGMENTS_ERROR_MPROTECT;
                           }
        }

      l->l_contiguous = 1;

      goto postmap;
    }

  /* Remember which part of the address space this object uses.  */
  l->l_map_start = c->mapstart + l->l_addr;
  l->l_map_end = l->l_map_start + maplength;
  l->l_contiguous = !has_holes;

  while (c < &loadcmds[nloadcmds])
    {
      if (c->mapend > c->mapstart ) {
        void* c_res = __mmap (NULL,
                      c->mapend - c->mapstart, c->prot,
                      MAP_COPY|MAP_FILE,
                      fd, c->mapoff);
        __mprotect((void*)l->l_addr + c->mapstart, c->mapend - c->mapstart, PROT_READ | PROT_WRITE);
        if(c_res == MAP_FAILED) {
          return DL_MAP_SEGMENTS_ERROR_MAP_SEGMENT;
        }
        memcpy((void*)l->l_addr + c->mapstart, c_res, c->mapend - c->mapstart);
        if (__mprotect((void*)l->l_addr + c->mapstart, c->mapend - c->mapstart, c->prot))
          return DL_MAP_SEGMENTS_ERROR_MAP_SEGMENT;
      }
        //void* c_res = __mmap (NULL,
      //                c->mapend - c->mapstart, c->prot,
      //                MAP_COPY|MAP_FILE,
      //                fd, c->mapoff);
      //  memcpy(dest + c->mapstart, c_res, c->mapend - c->mapstart);
      //  _
      //  l->l_addr + c->mapstart
      //}
      //    /* Map the segment contents from the file.  */
      //    && (__mmap ((void *) (l->l_addr + c->mapstart),
      //                c->mapend - c->mapstart, c->prot,
      //                MAP_FIXED|MAP_COPY|MAP_FILE,
      //                fd, c->mapoff)
      //        == MAP_FAILED))

    postmap:
       _dl_debug_printf("1\n");

      _dl_postprocess_loadcmd (l, header, c);
       _dl_debug_printf("2\n");

      if (c->allocend > c->dataend)
        {
          /* Extra zero pages should appear at the end of this segment,
             after the data mapped from the file.   */
          ElfW(Addr) zero, zeroend, zeropage;

          zero = l->l_addr + c->dataend;
          zeroend = l->l_addr + c->allocend;
          zeropage = ((zero + GLRO(dl_pagesize) - 1)
                      & ~(GLRO(dl_pagesize) - 1));

          if (zeroend < zeropage)
            /* All the extra data is in the last page of the segment.
               We can just zero it.  */
            zeropage = zeroend;

          if (zeropage > zero)
            {
              /* Zero the final part of the last page of the segment.  */
              if (__glibc_unlikely ((c->prot & PROT_WRITE) == 0))
                {
                  /* Dag nab it.  */
                  if (__mprotect ((caddr_t) (zero
                                             & ~(GLRO(dl_pagesize) - 1)),
                                  GLRO(dl_pagesize), c->prot|PROT_WRITE) < 0)
                    return DL_MAP_SEGMENTS_ERROR_MPROTECT;
                }
              memset ((void *) zero, '\0', zeropage - zero);
              if (__glibc_unlikely ((c->prot & PROT_WRITE) == 0))
                __mprotect ((caddr_t) (zero & ~(GLRO(dl_pagesize) - 1)),
                            GLRO(dl_pagesize), c->prot);
            }

          if (zeroend > zeropage)
            {
              /* Map the remaining zero pages in from the zero fill FD.  */
              ret = __mprotect((caddr_t) zeropage, zeroend - zeropage, PROT_READ|PROT_WRITE);
              if (__glibc_unlikely (ret))
                return DL_MAP_SEGMENTS_ERROR_MAP_ZERO_FILL;
              memset((caddr_t) zeropage, 0, zeroend - zeropage);
              ret = __mprotect((caddr_t) zeropage, zeroend - zeropage, c->prot);
              if (__glibc_unlikely (ret))
                return DL_MAP_SEGMENTS_ERROR_MAP_ZERO_FILL;
            }
        }

      ++c;
    }

  /* Notify ELF_PREFERRED_ADDRESS that we have to load this one
     fixed.  */
  ELF_FIXED_ADDRESS (loader, c->mapstart);
  _dl_debug_printf("return\n");

  return NULL;
}

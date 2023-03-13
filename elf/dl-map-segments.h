/* Map in a shared object's segments.  Generic version.
   Copyright (C) 1995-2018 Free Software Foundation, Inc.
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
   <http://www.gnu.org/licenses/>.  */

#include <dl-load.h>
#include <rtld-vessel.h>

/* This implementation assumes (as does the corresponding implementation
   of _dl_unmap_segments, in dl-unmap-segments.h) that shared objects
   are always laid out with all segments contiguous (or with gaps
   between them small enough that it's preferable to reserve all whole
   pages inside the gaps with PROT_NONE mappings rather than permitting
   other use of those parts of the address space).  */

#ifndef VESSEL_RTDL
static __always_inline const char *
_dl_map_segments (struct link_map *l, int fd,
                  const ElfW(Ehdr) *header, int type,
                  const struct loadcmd loadcmds[], size_t nloadcmds,
                  const size_t maplength, bool has_holes,
                  struct link_map *loader)
{
  const struct loadcmd *c = loadcmds;

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
      l->l_map_start = (ElfW(Addr)) __mmap ((void *) mappref, maplength,
                                            c->prot,
                                            MAP_COPY|MAP_FILE,
                                            fd, c->mapoff);
      if (__glibc_unlikely ((void *) l->l_map_start == MAP_FAILED))
        return DL_MAP_SEGMENTS_ERROR_MAP_SEGMENT;

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
                           PROT_NONE) < 0))
            return DL_MAP_SEGMENTS_ERROR_MPROTECT;
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
      if (c->mapend > c->mapstart
          /* Map the segment contents from the file.  */
          && (__mmap ((void *) (l->l_addr + c->mapstart),
                      c->mapend - c->mapstart, c->prot,
                      MAP_FIXED|MAP_COPY|MAP_FILE,
                      fd, c->mapoff)
              == MAP_FAILED))
        return DL_MAP_SEGMENTS_ERROR_MAP_SEGMENT;

    postmap:
      _dl_postprocess_loadcmd (l, header, c);

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
              caddr_t mapat;
              mapat = __mmap ((caddr_t) zeropage, zeroend - zeropage,
                              c->prot, MAP_ANON|MAP_PRIVATE|MAP_FIXED,
                              -1, 0);
              if (__glibc_unlikely (mapat == MAP_FAILED))
                return DL_MAP_SEGMENTS_ERROR_MAP_ZERO_FILL;
            }
        }

      ++c;
    }

  /* Notify ELF_PREFERRED_ADDRESS that we have to load this one
     fixed.  */
  ELF_FIXED_ADDRESS (loader, c->mapstart);

  return NULL;
}
#else
static __always_inline const char *
_dl_map_segments (struct link_map *l, int fd,
                  const ElfW(Ehdr) *header, int type,
                  const struct loadcmd loadcmds[], size_t nloadcmds,
                  const size_t maplength, bool has_holes,
                  struct link_map *loader)
{
  const struct loadcmd *c = loadcmds;
  struct minimal_ops *vops = NULL;
  //_dl_debug_printf("Vessel Version!!!\n");

  vops = vessel_get_ops();
  //_dl_debug_printf("After vessel_get_ops\n");

  int ret;
   const struct loadcmd *pre = loadcmds;
   ElfW(Addr) tstart = 0, tend, temp; 
   // size_t seg_size, seg_zero, seg_zeroend, seg_zeropage;
   if (__glibc_likely (type == ET_DYN)) {
     tend = ((maplength + GLRO(dl_pagesize) - 1)
                       & ~(GLRO(dl_pagesize) - 1));
     goto pre_postcnt;
     while (pre < &loadcmds[nloadcmds]) {
       temp = ((pre->mapend + GLRO(dl_pagesize) - 1)
                       & ~(GLRO(dl_pagesize) - 1));
       if (temp>tend) {
         tend = temp;
       }
 pre_postcnt:
       if (pre->allocend > pre->dataend) {
         temp = ((pre->allocend + GLRO(dl_pagesize) - 1)
                       & ~(GLRO(dl_pagesize) - 1));
       } else {
         temp = ((pre->dataend + GLRO(dl_pagesize) - 1)
                       & ~(GLRO(dl_pagesize) - 1));        
       }
       if (temp>tend) {
         tend = temp;
       }
       pre++;
     }

   }
   //_dl_debug_printf("After get count\n");


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
      // ElfW(Addr) mappref
      //   = (ELF_PREFERRED_ADDRESS (loader, maplength,
      //                             c->mapstart & GLRO(dl_use_load_bias))
      //      - MAP_BASE_ADDR (l));

      /* Remember which part of the address space this object uses.  */
      void * res = __mmap ((void *) NULL, maplength, c->prot, MAP_COPY|MAP_FILE, fd, c->mapoff);
      //_dl_debug_printf("After __mmap offset:%lu\n", c->mapoff);

      // void * dest = res;
      v_aligned_alloc_t v_aligned_alloc = (v_aligned_alloc_t) vops->aligned_alloc;
      //_dl_debug_printf("After get v_aligned_alloc\n");
      //void * dest = __mmap (NULL, maplength, c->prot | PROT_WRITE, MAP_ANON|MAP_PRIVATE|MAP_FIXED, -1, 0);
      void * dest = v_aligned_alloc(VESSEL_ALIGN_SIZE, VESSEL_UPPER_ALIGN(tend - tstart));
      _dl_debug_printf("from 0x%0*lx ", (int) sizeof(void*) * 2, (long unsigned int) dest);
      _dl_debug_printf("to 0x%0*lx\n", (int) sizeof(void*) * 2, (long unsigned int) dest + VESSEL_UPPER_ALIGN(tend - tstart));

      //struct stat64 st;
      //__fstat64(fd, &st);
      //_dl_debug_printf("After __fstat64\n");

      //size_t f_size = st.st_size;
      //_dl_debug_printf("After fsize: %lu\n", st.st_size);

      memcpy(dest, res, c->dataend - c->mapstart);
      //_dl_debug_printf("After memcpy: %lu\n", c->dataend - c->mapstart);

      //__munmap(res, maplength);

      if(__mprotect(dest, VESSEL_UPPER_ALIGN(maplength), c->prot)<0) {
         _dl_debug_printf("Fail to mprotect for %d\n", errno);
         return DL_MAP_SEGMENTS_ERROR_MPROTECT;
      }

      l->l_map_start = (ElfW(Addr)) dest;
      if (__glibc_unlikely ((void *) l->l_map_start == MAP_FAILED)) {
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
                              _dl_debug_printf("Fail to __mprotect\n");
                              return DL_MAP_SEGMENTS_ERROR_MPROTECT;
                           }
        }

      l->l_contiguous = 1;
      //_dl_debug_printf("Before goto postmap\n");

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
        if (c_res == MAP_FAILED) {
          return DL_MAP_SEGMENTS_ERROR_MAP_SEGMENT;
        }
        if(__mprotect((void*)l->l_addr + c->mapstart,
              VESSEL_UPPER_ALIGN(c->mapend - c->mapstart), PROT_READ | PROT_WRITE) < 0)
          return DL_MAP_SEGMENTS_ERROR_MPROTECT;
        memcpy((void*)l->l_addr + c->mapstart, c_res, c->mapend - c->mapstart);
        if (__mprotect((void*)l->l_addr + c->mapstart, VESSEL_UPPER_ALIGN(c->mapend - c->mapstart), c->prot))
          return DL_MAP_SEGMENTS_ERROR_MPROTECT;
      }
      //if (c->mapend > c->mapstart
      //    /* Map the segment contents from the file.  */
      //    && (__mmap ((void *) (l->l_addr + c->mapstart),
      //                c->mapend - c->mapstart, c->prot,
      //                MAP_FIXED|MAP_COPY|MAP_FILE,
      //                fd, c->mapoff)
      //        == MAP_FAILED))
      //  return DL_MAP_SEGMENTS_ERROR_MAP_SEGMENT;

    postmap:

      _dl_postprocess_loadcmd (l, header, c);

      if (c->allocend > c->dataend)
        {
          /* Extra zero pages should appear at the end of this segment,
             after the data mapped from the file.   */
          ElfW(Addr) zero, zeroend, zeropage;
          //_dl_debug_printf("c->allocend > c->dataend\n");

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
             //_dl_debug_printf("zeropage > zero\n");

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
             //_dl_debug_printf("after memset: %lu\n", zeropage - zero);

              if (__glibc_unlikely ((c->prot & PROT_WRITE) == 0)) {
                if (__mprotect ((caddr_t) (zero & ~(GLRO(dl_pagesize) - 1)),
                            GLRO(dl_pagesize), c->prot) < 0)
                  return DL_MAP_SEGMENTS_ERROR_MPROTECT;
              }
            }

          if (zeroend > zeropage)
            {
              //int ret;
             //_dl_debug_printf("zeroend > zeropage\n");
              /* Map the remaining zero pages in from the zero fill FD.  */
              //caddr_t mapat;
              //mapat = __mmap ((caddr_t) zeropage, zeroend - zeropage,
              //                c->prot, MAP_ANON|MAP_PRIVATE|MAP_FIXED,
              //                -1, 0);
              //if (__glibc_unlikely (mapat == MAP_FAILED))
              //  return DL_MAP_SEGMENTS_ERROR_MAP_ZERO_FILL;
              ret = __mprotect((caddr_t) zeropage, VESSEL_UPPER_ALIGN(zeroend - zeropage), c->prot|PROT_WRITE);
              if (__glibc_unlikely (ret < 0))
                return DL_MAP_SEGMENTS_ERROR_MAP_ZERO_FILL;
              memset((caddr_t) zeropage, 0, zeroend - zeropage);
              ret = __mprotect((caddr_t) zeropage, VESSEL_UPPER_ALIGN(zeroend - zeropage), c->prot);
              if (__glibc_unlikely (ret < 0))
                return DL_MAP_SEGMENTS_ERROR_MAP_ZERO_FILL;
            }
        }
      ++c;
    }
  /* Notify ELF_PREFERRED_ADDRESS that we have to load this one
     fixed.  */
  ELF_FIXED_ADDRESS (loader, c->mapstart);

  //_dl_debug_printf("Buttom\n");

  return NULL;
}
#endif
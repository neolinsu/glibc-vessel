/* Load a shared object at run time.
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

#include <dlfcn.h>
#include <libintl.h>
#include <stddef.h>
#include <unistd.h>
#include <ldsodefs.h>
#include <stdio.h>

#if !defined SHARED && IS_IN (libdl)

void *
dlopenh (const char *file, int mode, void *hint)
{
  return __dlopen (file, mode, RETURN_ADDRESS (0));
}
static_link_warning (dlopenh)

#else

struct dlopenh_args
{
  /* The arguments for dlopen_doit.  */
  const char *file;
  int mode;
  void *hint;
  /* The return value of dlopen_doit.  */
  void *new;
  /* Address of the caller.  */
  const void *caller;
};


/* Non-shared code has no support for multiple namespaces.  */
# ifdef SHARED
#  define NS __LM_ID_CALLER
# else
#  define NS LM_ID_BASE
# endif


static void
dlopenh_doit (void *a)
{
  struct dlopenh_args *args = (struct dlopenh_args *) a;

  if (args->mode & ~(RTLD_BINDING_MASK | RTLD_NOLOAD | RTLD_DEEPBIND
		     | RTLD_GLOBAL | RTLD_LOCAL | RTLD_NODELETE
		     | __RTLD_SPROF))
    _dl_signal_error (0, NULL, NULL, _("invalid mode parameter"));

  args->new = GLRO(dl_openh) (args->file ?: "", args->mode | __RTLD_DLOPEN, args->hint,
			     args->caller,
			     args->file == NULL ? LM_ID_BASE : NS,
			     __dlfcn_argc, __dlfcn_argv, __environ);
}


void *
__dlopenh (const char *file, int mode, void* hint DL_CALLER_DECL)
{
# ifdef SHARED
  if (!rtld_active ()) {
    _dl_signal_error (0, NULL, NULL, _("Do not supported!"));
    return _dlfcn_hook->dlopen (file, mode, DL_CALLER);
  }
# endif

  struct dlopenh_args args;
  args.file = file;
  args.mode = mode;
  args.hint = hint;
  args.caller = DL_CALLER;

# ifdef SHARED
  return _dlerror_run (dlopenh_doit, &args) ? NULL : args.new;
# else
  if (_dlerror_run (dlopenh_doit, &args))
    return NULL;

  __libc_register_dl_open_hook ((struct link_map *) args.new);
  __libc_register_dlfcn_hook ((struct link_map *) args.new);

  return args.new;
# endif
}
# ifdef SHARED
#  include <shlib-compat.h>
strong_alias (__dlopenh, __dlopenh_check)
versioned_symbol (libdl, __dlopenh_check, dlopenh, GLIBC_2_1);
# endif
#endif

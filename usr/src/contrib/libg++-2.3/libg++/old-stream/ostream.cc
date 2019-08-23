// This may look like C code, but it is really -*- C++ -*-
/* 
Copyright (C) 1989 Free Software Foundation
    written by Doug Lea (dl@rocky.oswego.edu)

This file is part of the GNU C++ Library.  This library is free
software; you can redistribute it and/or modify it under the terms of
the GNU Library General Public License as published by the Free
Software Foundation; either version 2 of the License, or (at your
option) any later version.  This library is distributed in the hope
that it will be useful, but WITHOUT ANY WARRANTY; without even the
implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE.  See the GNU Library General Public License for more details.
You should have received a copy of the GNU Library General Public
License along with this library; if not, write to the Free Software
Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
*/

/* *** Version 1.2 -- nearly 100% AT&T 1.2 compatible *** */

#ifdef __GNUG__
#pragma implementation
#endif
#include <stream.h>
#include <stdarg.h>
#include <values.h>
#include <ctype.h>
#include <Obstack.h>

ostream::ostream(streambuf* s)
     : bp(s), state(_good), ownbuf(0) {}

ostream::ostream(int sz, char* buf)
     : state(_good), ownbuf(1)
{
  if (buf == 0) 
  {
    buf = new char[sz];
    bp = new streambuf(buf, sz);
    bp->setbuf(buf, sz);
    bp->alloc = 1;
  }
  else
  {
    bp = new streambuf(buf, sz);
    bp->alloc = 0;
  }
}


ostream::ostream(const char* filename, io_mode m, access_mode a)
     : state(_good), ownbuf(1)
{
  bp = new Filebuf(filename, m, a);
}

ostream::ostream(const char* filename, const char* m)
     : state(_good), ownbuf(1)
{
  bp = new Filebuf(filename, m);
}

ostream::ostream(int filedesc, io_mode m)
     : state(_good), ownbuf(1)
{
  bp = new Filebuf(filedesc, m);
}

ostream::ostream(FILE* fileptr)
     : state(_good), ownbuf(1)
{
  bp = new Filebuf(fileptr);
}

ostream::ostream(int filedesc)
     : state(_good), ownbuf(1)
{
  bp = new filebuf(filedesc);
}

ostream::ostream(int filedesc, char* buf, int buflen)
     : state(_good), ownbuf(1)
{
  bp = new filebuf(filedesc, buf, buflen);
}

ostream::~ostream()
{
  if (ownbuf) delete bp;
}

ostream&  ostream::open(const char* filename, io_mode m, access_mode a)
{
  return failif(bp->open(filename, m, a) == 0);
}

ostream&  ostream::open(const char* filename, const char* m)
{
  return failif(bp->open(filename, m) == 0);
}

ostream&  ostream::open(int  filedesc, io_mode m)
{
  return failif(bp->open(filedesc, m) == 0);
}

ostream&  ostream::open(FILE* fileptr)
{
  return failif(bp->open(fileptr) == 0);
}

ostream&  ostream::open(const char* filenam, open_mode m)
{
  return failif(bp->open(filenam, m) == 0);
}

ostream& ostream::form(const char* fmt...)
{
  va_list args;
  va_start(args, fmt);
  char buf[BUFSIZ];
#ifndef HAVE_VPRINTF
  FILE b;
  b._flag = _IOWRT|_IOSTRG;
  b._ptr = buf;
  b._cnt = BUFSIZ;
  _doprnt(fmt, args, &b);
  putc('\0', &b);
#else
  vsprintf(buf, fmt, args);
#endif
  va_end(args);
  return put(buf);
}

ostream& ostream::operator<<(short  n)
{ 
  return put(itoa(long(n)));
}

ostream& ostream::operator<<(unsigned short n)
{ 
  return put(itoa((unsigned long)(n)));
}

ostream& ostream::operator<<(int    n)
{ 
  return put(itoa(long(n)));
}

ostream& ostream::operator<<(unsigned int n)
{ 
  return put(itoa((unsigned long)(n)));
}

ostream& ostream::operator<<(long   n)
{ 
  return put(itoa(n));
}

ostream& ostream::operator<<(unsigned long n)
{ 
  return put(itoa(n));
}

#ifdef __GNUG__
#ifndef VMS
ostream& ostream::operator<<(long long n)
{ 
  return put(itoa(n));
}

ostream& ostream::operator<<(unsigned long long n)
{ 
  return put(itoa(n));
}
#endif
#endif
ostream& ostream::operator<<(float  n)
{ 
  return put(dtoa(double(n)));
}

ostream& ostream::operator<<(double n)
{ 
  return put(dtoa(n));
}

ostream& ostream::operator<<(const void* p)
{ 
  put("0x");
  return put(itoa((unsigned long)(p), 16));
}


const char* ostream::name()
{
  return bp->name();
}

void ostream::error()
{
  bp->error();
}

#ifndef DEFAULT_filebuf

ostream  cerr(stderr);
ostream  cout(stdout);

#else

static char cerrbuf[1];
static char coutbuf[BUFSIZE];

ostream cerr(2, cerrbuf, 1);
ostream cout(1, coutbuf, BUFSIZE);

#endif

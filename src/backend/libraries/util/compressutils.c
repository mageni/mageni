/**
 * SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-FileCopyrightText: Copyright 2013-2019 Greenbone Networks GmbH
 * SPDX-FileComment: Functions related to data compression (gzip format.)
 * SPDX-FileContributor: Mageni Security LLC
 * 
 */

#if !defined(ZLIB_CONST)
#define ZLIB_CONST
#endif

#include "compressutils.h"

#include <glib.h> /* for g_free, g_malloc0 */
#include <zlib.h> /* for z_stream, Z_NULL, Z_OK, Z_BUF_ERROR, Z_STREAM_END */

/**
 * @brief Compresses data in src buffer.
 *
 * @param[in]   src     Buffer of data to compress.
 * @param[in]   srclen  Length of data to compress.
 * @param[out]  dstlen  Length of compressed data.
 *
 * @return Pointer to compressed data if success, NULL otherwise.
 */
void *
mgn_compress (const void *src, unsigned long srclen, unsigned long *dstlen)
{
  unsigned long buflen = srclen * 2;

  if (src == NULL || dstlen == NULL)
    return NULL;

  if (buflen < 30)
    buflen = 30;

  while (1)
    {
      int err;
      void *buffer;
      z_stream strm;

      /* Initialize deflate state */
      strm.zalloc = Z_NULL;
      strm.zfree = Z_NULL;
      strm.opaque = Z_NULL;
      strm.avail_in = srclen;
#ifdef z_const
      strm.next_in = src;
#else
      /* Workaround for older zlib. */
      strm.next_in = (void *) src;
#endif
      if (deflateInit (&strm, Z_DEFAULT_COMPRESSION) != Z_OK)
        return NULL;

      buffer = g_malloc0 (buflen);
      strm.avail_out = buflen;
      strm.next_out = buffer;

      err = deflate (&strm, Z_SYNC_FLUSH);
      deflateEnd (&strm);
      switch (err)
        {
        case Z_OK:
        case Z_STREAM_END:
          if (strm.avail_out != 0)
            {
              *dstlen = strm.total_out;
              return buffer;
            }
          /* Fallthrough. */
        case Z_BUF_ERROR:
          g_free (buffer);
          buflen *= 2;
          break;

        default:
          g_free (buffer);
          return NULL;
        }
    }
}

/**
 * @brief Uncompresses data in src buffer.
 *
 * @param[in]   src     Buffer of data to uncompress.
 * @param[in]   srclen  Length of data to uncompress.
 * @param[out]  dstlen  Length of uncompressed data.
 *
 * @return Pointer to uncompressed data if success, NULL otherwise.
 */
void *
mgn_uncompress (const void *src, unsigned long srclen, unsigned long *dstlen)
{
  unsigned long buflen = srclen * 2;

  if (src == NULL || dstlen == NULL)
    return NULL;

  while (1)
    {
      int err;
      void *buffer;
      z_stream strm;

      /* Initialize inflate state */
      strm.zalloc = Z_NULL;
      strm.zfree = Z_NULL;
      strm.opaque = Z_NULL;
      strm.avail_in = srclen;
#ifdef z_const
      strm.next_in = src;
#else
      /* Workaround for older zlib. */
      strm.next_in = (void *) src;
#endif
      /*
       * From: http://www.zlib.net/manual.html
       * Add 32 to windowBits to enable zlib and gzip decoding with automatic
       * header detection.
       */
      if (inflateInit2 (&strm, 15 + 32) != Z_OK)
        return NULL;

      buffer = g_malloc0 (buflen);
      strm.avail_out = buflen;
      strm.next_out = buffer;

      err = inflate (&strm, Z_SYNC_FLUSH);
      inflateEnd (&strm);
      switch (err)
        {
        case Z_OK:
        case Z_STREAM_END:
          if (strm.avail_out != 0)
            {
              *dstlen = strm.total_out;
              return buffer;
            }
          /* Fallthrough. */
        case Z_BUF_ERROR:
          g_free (buffer);
          buflen *= 2;
          break;

        default:
          g_free (buffer);
          return NULL;
        }
    }
}

/**
 * @brief Compresses data in src buffer, gzip format compatible.
 *
 * @param[in]   src     Buffer of data to compress.
 * @param[in]   srclen  Length of data to compress.
 * @param[out]  dstlen  Length of compressed data.
 *
 * @return Pointer to compressed data if success, NULL otherwise.
 */
void *
mgn_compress_gzipheader (const void *src, unsigned long srclen,
                         unsigned long *dstlen)
{
  unsigned long buflen = srclen * 2;
  int windowsBits = 15;
  int GZIP_ENCODING = 16;

  if (src == NULL || dstlen == NULL)
    return NULL;

  if (buflen < 30)
    buflen = 30;

  while (1)
    {
      int err;
      void *buffer;
      z_stream strm;

      /* Initialize deflate state */
      strm.zalloc = Z_NULL;
      strm.zfree = Z_NULL;
      strm.opaque = Z_NULL;
      strm.avail_in = srclen;
#ifdef z_const
      strm.next_in = src;
#else
      /* Workaround for older zlib. */
      strm.next_in = (void *) src;
#endif

      if (deflateInit2 (&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
                        windowsBits | GZIP_ENCODING, 8, Z_DEFAULT_STRATEGY)
          != Z_OK)
        return NULL;

      buffer = g_malloc0 (buflen);
      strm.avail_out = buflen;
      strm.next_out = buffer;

      err = deflate (&strm, Z_FINISH);
      deflateEnd (&strm);
      switch (err)
        {
        case Z_OK:
        case Z_STREAM_END:
          if (strm.avail_out != 0)
            {
              *dstlen = strm.total_out;
              return buffer;
            }
          /* Fallthrough. */
        case Z_BUF_ERROR:
          g_free (buffer);
          buflen *= 2;
          break;

        default:
          g_free (buffer);
          return NULL;
        }
    }
}

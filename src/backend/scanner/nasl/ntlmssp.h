/**
 * SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-FileCopyrightText: Copyright (C) 2010-2019 Greenbone Networks GmbH
 * SPDX-FileComment: This file will be deleted as SMBClient/RPCClient will take this function.
 * SPDX-FileContributor: Mageni Security LLC
 * 
 */

#ifndef _NTLMSSP_H_
#define _NTLMSSP_H_
#include "byteorder.h"
#include "hmacmd5.h"
#include "md5.h"
#include "proto.h"
#include "smb_crypt.h"

#ifndef uchar
#define uchar unsigned char
#endif

#ifndef uint8
#define uint8 uint8_t
#endif

void
ntlmssp_genauth_ntlmv2 (char *user, char *domain, char *address_list,
                        int address_list_len, char *challenge_data,
                        uint8_t *lm_response, uint8_t *nt_response,
                        uint8_t *session_key, unsigned char *ntlmv2_hash);
void
ntlmssp_genauth_ntlm2 (char *password, uint8_t pass_len, uint8_t *lm_response,
                       uint8_t *nt_response, uint8_t *session_key,
                       char *challenge_data, unsigned char *nt_hash);

void
ntlmssp_genauth_ntlm (char *password, uint8_t pass_len, uint8_t *lm_response,
                      uint8_t *nt_response, uint8_t *session_key,
                      char *challenge_data, unsigned char *nt_hash,
                      int neg_flags);
uint8_t *
ntlmssp_genauth_keyexchg (uint8_t *session_key, char *challenge_data,
                          unsigned char *nt_hash, uint8_t *new_sess_key);

#endif

/**
 * SPDX-License-Identifier: GPL-2.0-only
 * SPDX-FileCopyrightText: Copyright (C) 2002 - 2003 Michel Arboi and Renaud Deraison
 * SPDX-FileContributor: Mageni Security LLC
 * 
 */

#ifndef EXEC_H_INCLUDED
#define EXEC_H_INCLUDED

#include "nasl_lex_ctxt.h"

tree_cell * nasl_exec (lex_ctxt *, tree_cell *);

long int cell_cmp (lex_ctxt *, tree_cell *, tree_cell *);

tree_cell * cell2atom (lex_ctxt *, tree_cell *);

#endif

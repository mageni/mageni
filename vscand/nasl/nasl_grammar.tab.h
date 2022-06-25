/* A Bison parser, made by GNU Bison 3.5.1.  */

/* Bison interface for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015, 2018-2020 Free Software Foundation,
   Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* Undocumented macros, especially those whose name start with YY_,
   are private implementation details.  Do not rely on them.  */

#ifndef YY_NASL_NASL_GRAMMAR_TAB_H_INCLUDED
# define YY_NASL_NASL_GRAMMAR_TAB_H_INCLUDED
/* Debug traces.  */
#ifndef YYDEBUG
# define YYDEBUG 1
#endif
#if YYDEBUG
extern int nasldebug;
#endif

/* Token type.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
  enum yytokentype
  {
    IF = 258,
    ELSE = 259,
    EQ = 260,
    NEQ = 261,
    SUPEQ = 262,
    INFEQ = 263,
    OR = 264,
    AND = 265,
    MATCH = 266,
    NOMATCH = 267,
    REP = 268,
    FOR = 269,
    REPEAT = 270,
    UNTIL = 271,
    FOREACH = 272,
    WHILE = 273,
    BREAK = 274,
    CONTINUE = 275,
    FUNCTION = 276,
    RETURN = 277,
    INCLUDE = 278,
    LOCAL = 279,
    GLOBAL = 280,
    PLUS_PLUS = 281,
    MINUS_MINUS = 282,
    L_SHIFT = 283,
    R_SHIFT = 284,
    R_USHIFT = 285,
    EXPO = 286,
    PLUS_EQ = 287,
    MINUS_EQ = 288,
    MULT_EQ = 289,
    DIV_EQ = 290,
    MODULO_EQ = 291,
    L_SHIFT_EQ = 292,
    R_SHIFT_EQ = 293,
    R_USHIFT_EQ = 294,
    RE_MATCH = 295,
    RE_NOMATCH = 296,
    ARROW = 297,
    IDENT = 298,
    STRING1 = 299,
    STRING2 = 300,
    INTEGER = 301,
    NOT = 302,
    UMINUS = 303,
    BIT_NOT = 304
  };
#endif

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
union YYSTYPE
{
#line 62 "/home/yeshua/platform/vscand/nasl/nasl_grammar.y"

  long int       num;
  char		*str;
  struct asciiz {
    char	*val;
    int		len;
  } data;
  tree_cell	*node;

#line 117 "nasl_grammar.tab.h"

};
typedef union YYSTYPE YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif



int naslparse (naslctxt * parm);

#endif /* !YY_NASL_NASL_GRAMMAR_TAB_H_INCLUDED  */

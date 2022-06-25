<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet
    version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:str="http://exslt.org/strings"
    extension-element-prefixes="str">
  <xsl:strip-space elements="*"/>

<!--
Copyright (C) 2010-2018 Greenbone Networks GmbH

SPDX-License-Identifier: GPL-2.0-or-later

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
-->

<!-- Greenbone Management Protocol (GMP) RNC support templates. -->

  <!-- Helpers. -->

<!-- This is called within a PRE. -->
<xsl:template name="wrap">
  <xsl:param name="string"></xsl:param>

  <xsl:choose>
    <xsl:when test="contains($string, '&#10;')">
      <xsl:for-each select="str:tokenize($string, '&#10;')">
        <xsl:call-template name="wrap-line">
          <xsl:with-param name="string"><xsl:value-of select="."/></xsl:with-param>
        </xsl:call-template>
        <xsl:text>
</xsl:text>
      </xsl:for-each>
    </xsl:when>
    <xsl:otherwise>
      <xsl:call-template name="wrap-line">
        <xsl:with-param name="string"><xsl:value-of select="$string"/></xsl:with-param>
      </xsl:call-template>
    </xsl:otherwise>
  </xsl:choose>
</xsl:template>

<!-- This is called within a PRE. -->
<xsl:template name="wrap-line">
  <xsl:param name="string"></xsl:param>

  <xsl:variable name="to-next-newline">
    <xsl:value-of select="substring-before($string, '&#10;')"/>
  </xsl:variable>

  <xsl:choose>
    <xsl:when test="string-length($string) = 0">
      <!-- The string is empty. -->
    </xsl:when>
    <xsl:when test="(string-length($to-next-newline) = 0) and (substring($string, 1, 1) != '&#10;')">
      <!-- A single line missing a newline, output up to the edge. -->
<xsl:value-of select="substring($string, 1, 76)"/>
      <xsl:if test="string-length($string) &gt; 76">&#8629;
<xsl:call-template name="wrap-line">
  <xsl:with-param name="string"><xsl:value-of select="substring($string, 77, string-length($string))"/></xsl:with-param>
</xsl:call-template>
      </xsl:if>
    </xsl:when>
    <xsl:when test="(string-length($to-next-newline) + 1 &lt; string-length($string)) and (string-length($to-next-newline) &lt; 76)">
      <!-- There's a newline before the edge, so output the line. -->
<xsl:value-of select="substring($string, 1, string-length($to-next-newline) + 1)"/>
<xsl:call-template name="wrap-line">
  <xsl:with-param name="string"><xsl:value-of select="substring($string, string-length($to-next-newline) + 2, string-length($string))"/></xsl:with-param>
</xsl:call-template>
    </xsl:when>
    <xsl:otherwise>
      <!-- Any newline comes after the edge, so output up to the edge. -->
<xsl:value-of select="substring($string, 1, 76)"/>
      <xsl:if test="string-length($string) &gt; 76">&#8629;
<xsl:call-template name="wrap-line">
  <xsl:with-param name="string"><xsl:value-of select="substring($string, 77, string-length($string))"/></xsl:with-param>
</xsl:call-template>
      </xsl:if>
    </xsl:otherwise>
  </xsl:choose>

</xsl:template>

  <!-- Preamble. -->

  <xsl:template name="preamble">
    <xsl:text>### Preamble

start = command | response

command
  = </xsl:text>
    <xsl:for-each select="command">
      <xsl:value-of select="name"/>
      <xsl:if test="following-sibling::command">
        <xsl:call-template name="newline"/>
        <xsl:text>    | </xsl:text>
      </xsl:if>
    </xsl:for-each>
    <xsl:text>

response
  = </xsl:text>
    <xsl:for-each select="command">
      <xsl:value-of select="name"/>
      <xsl:text>_response</xsl:text>
      <xsl:if test="following-sibling::command">
        <xsl:call-template name="newline"/>
        <xsl:text>    | </xsl:text>
      </xsl:if>
    </xsl:for-each>
    <xsl:call-template name="newline"/>
  </xsl:template>

  <!-- Commands. -->

  <xsl:template name="rnc-type">
    <xsl:choose>
      <xsl:when test="count (alts) &gt; 0">
        <xsl:for-each select="alts/alt">
          <xsl:choose>
            <xsl:when test="following-sibling::alt and preceding-sibling::alt">
              <xsl:text>|</xsl:text>
              <xsl:value-of select="."/>
            </xsl:when>
            <xsl:when test="count (following-sibling::alt) = 0">
              <xsl:text>|</xsl:text>
              <xsl:value-of select="."/>
              <xsl:text>" }</xsl:text>
            </xsl:when>
            <xsl:otherwise>
              <xsl:text>xsd:token { pattern = "</xsl:text>
              <xsl:value-of select="."/>
            </xsl:otherwise>
          </xsl:choose>
        </xsl:for-each>
      </xsl:when>
      <xsl:otherwise>
        <xsl:value-of select="normalize-space(text())"/>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <xsl:template name="attrib" match="attrib">
    <xsl:if test="($rnc-comments = 1) and summary">
      <xsl:text># </xsl:text>
      <xsl:value-of select="normalize-space(summary)"/>
      <xsl:text>.</xsl:text>
      <xsl:call-template name="newline"/>
      <xsl:text>       </xsl:text>
    </xsl:if>
    <xsl:text>attribute </xsl:text>
    <xsl:value-of select="name"/>
    <xsl:text> { </xsl:text>
    <xsl:for-each select="type">
      <xsl:call-template name="rnc-type"/>
    </xsl:for-each>
    <xsl:text> }</xsl:text>
    <xsl:choose>
      <xsl:when test="required=1"></xsl:when>
      <xsl:otherwise><xsl:text>?</xsl:text></xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <xsl:template name="c" match="c">
    <xsl:value-of select="text()"/>
  </xsl:template>

  <xsl:template name="e" match="e">
    <xsl:param name="parent-name"/>
    <xsl:param name="parent"/>
    <xsl:variable name="name" select="text()"/>
    <xsl:choose>
      <xsl:when test="$parent/ele[name=$name]">
        <xsl:value-of select="$parent-name"/>
        <xsl:value-of select="$name"/>
      </xsl:when>
      <xsl:otherwise>
        <!-- Presume there is a top level element with this name. -->
        <xsl:value-of select="$name"/>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <xsl:template name="r" match="r">
    <xsl:param name="parent-name"/>
    <xsl:value-of select="text()"/>
    <xsl:text>_response</xsl:text>
  </xsl:template>

  <xsl:template name="t" match="t">
    <xsl:choose>
      <xsl:when test="count (alts) &gt; 0">
        <xsl:for-each select="alts/alt">
          <xsl:choose>
            <xsl:when test="following-sibling::alt and preceding-sibling::alt">
              <xsl:text>|</xsl:text>
              <xsl:value-of select="."/>
            </xsl:when>
            <xsl:when test="count (following-sibling::alt) = 0">
              <xsl:text>|</xsl:text>
              <xsl:value-of select="."/>
              <xsl:text>" }</xsl:text>
            </xsl:when>
            <xsl:otherwise>
              <xsl:text>xsd:token { pattern = "</xsl:text>
              <xsl:value-of select="."/>
            </xsl:otherwise>
          </xsl:choose>
        </xsl:for-each>
      </xsl:when>
      <xsl:otherwise>
        <xsl:value-of select="normalize-space(text())"/>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <xsl:template name="pattern-part">
    <xsl:param name="parent-name"/>
    <xsl:param name="parent"/>
    <xsl:choose>
      <xsl:when test="name()='any'">
        <xsl:for-each select="*">
          <xsl:call-template name="pattern-part">
            <xsl:with-param name="parent-name" select="$parent-name"/>
            <xsl:with-param name="parent" select="$parent"/>
          </xsl:call-template>
        </xsl:for-each>
        <xsl:text>*</xsl:text>
      </xsl:when>
      <xsl:when test="name()='attrib'">
        <xsl:call-template name="attrib"/>
      </xsl:when>
      <xsl:when test="name()='c'">
        <xsl:call-template name="c"/>
      </xsl:when>
      <xsl:when test="name()='e'">
        <xsl:call-template name="e">
          <xsl:with-param name="parent-name" select="$parent-name"/>
          <xsl:with-param name="parent" select="$parent"/>
        </xsl:call-template>
      </xsl:when>
      <xsl:when test="name()='g'">
        <xsl:text>( </xsl:text>
        <xsl:for-each select="*">
          <xsl:choose>
            <xsl:when test="preceding-sibling::*">
              <xsl:text>           &amp; </xsl:text>
            </xsl:when>
            <xsl:otherwise>
            </xsl:otherwise>
          </xsl:choose>
          <xsl:call-template name="pattern-part">
            <xsl:with-param name="parent-name" select="$parent-name"/>
            <xsl:with-param name="parent" select="$parent"/>
          </xsl:call-template>
          <xsl:if test="following-sibling::*">
            <xsl:call-template name="newline"/>
          </xsl:if>
        </xsl:for-each>
        <xsl:text> )</xsl:text>
      </xsl:when>
      <xsl:when test="name()='o'">
        <xsl:for-each select="*">
          <xsl:call-template name="pattern-part">
            <xsl:with-param name="parent-name" select="$parent-name"/>
            <xsl:with-param name="parent" select="$parent"/>
          </xsl:call-template>
        </xsl:for-each>
        <xsl:text>?</xsl:text>
      </xsl:when>
      <xsl:when test="name()='or'">
        <xsl:text>( </xsl:text>
        <xsl:for-each select="*">
          <xsl:choose>
            <xsl:when test="preceding-sibling::*">
              <xsl:text>           | </xsl:text>
            </xsl:when>
            <xsl:otherwise>
            </xsl:otherwise>
          </xsl:choose>
          <xsl:call-template name="pattern-part">
            <xsl:with-param name="parent-name" select="$parent-name"/>
            <xsl:with-param name="parent" select="$parent"/>
          </xsl:call-template>
          <xsl:if test="following-sibling::*">
            <xsl:call-template name="newline"/>
          </xsl:if>
        </xsl:for-each>
        <xsl:text> )</xsl:text>
      </xsl:when>
      <xsl:when test="name()='r'">
        <xsl:call-template name="r">
          <xsl:with-param name="parent-name" select="$parent-name"/>
        </xsl:call-template>
      </xsl:when>
      <xsl:when test="name()='t'">
      </xsl:when>
      <xsl:otherwise>
        ERROR
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <xsl:template name="pattern" match="pattern">
    <xsl:param name="parent-name"/>
    <xsl:param name="parent"/>
    <xsl:choose>
      <xsl:when test="(count (*) = 0) and (string-length (normalize-space (text ())) = 0)">
        <xsl:text>       ""</xsl:text>
        <xsl:call-template name="newline"/>
      </xsl:when>
      <xsl:when test="(count (t) = 0) and (string-length (normalize-space (text ())) = 0)">
      </xsl:when>
      <xsl:when test="count (t) = 0">
        <xsl:text>       </xsl:text>
        <xsl:value-of select="normalize-space (text())"/>
        <xsl:call-template name="newline"/>
      </xsl:when>
      <xsl:otherwise>
        <xsl:text>       </xsl:text>
        <!-- There should be only one t. -->
        <xsl:choose>
          <xsl:when test="(count (*[name()!='t']) = 0)">
          </xsl:when>
          <xsl:otherwise>
            <xsl:text>text # RNC limitation: </xsl:text>
          </xsl:otherwise>
        </xsl:choose>
        <xsl:for-each select="t">
          <xsl:call-template name="t"/>
          <xsl:call-template name="newline"/>
        </xsl:for-each>
      </xsl:otherwise>
    </xsl:choose>
    <xsl:variable
      name="empty"
      select="(count (t) = 0) and (string-length (normalize-space (text ())) = 0)"/>
    <xsl:for-each select="*[name()!='t']">
      <xsl:choose>
        <xsl:when test="preceding-sibling::*">
          <xsl:text>       &amp; </xsl:text>
        </xsl:when>
        <xsl:when test="$empty">
          <xsl:text>       </xsl:text>
        </xsl:when>
        <xsl:otherwise>
          <xsl:text>       &amp; </xsl:text>
        </xsl:otherwise>
      </xsl:choose>
      <xsl:call-template name="pattern-part">
        <xsl:with-param name="parent-name" select="$parent-name"/>
        <xsl:with-param name="parent" select="$parent"/>
      </xsl:call-template>
      <xsl:call-template name="newline"/>
    </xsl:for-each>
  </xsl:template>

  <xsl:template name="ele">
    <xsl:param name="parent-name"/>
    <xsl:if test="($rnc-comments = 1) and summary">
      <xsl:text># </xsl:text>
      <xsl:value-of select="normalize-space(summary)"/>
      <xsl:text>.</xsl:text>
      <xsl:call-template name="newline"/>
    </xsl:if>
    <xsl:choose>
      <xsl:when test="type">
        <xsl:variable name="command-name" select="concat ($parent-name, name)"/>
        <xsl:value-of select="$command-name"/>
        <xsl:call-template name="newline"/>
        <xsl:text> = element </xsl:text>
        <xsl:value-of select="name"/>
        <xsl:text>    # type </xsl:text>
        <xsl:value-of select="type"/>
        <xsl:call-template name="newline"/>
        <xsl:text>     {</xsl:text>
        <xsl:call-template name="newline"/>
        <xsl:variable name="type" select="type"/>
        <xsl:variable name="parent" select="/protocol/element[name=$type]"/>
        <xsl:for-each select="/protocol/element[name=$type]/pattern">
          <xsl:call-template name="pattern">
            <xsl:with-param name="parent-name" select="concat ($type, '_')"/>
            <xsl:with-param name="parent" select="$parent"/>
          </xsl:call-template>
        </xsl:for-each>
        <xsl:text>     }</xsl:text>
        <xsl:call-template name="newline"/>
      </xsl:when>
      <xsl:otherwise>
        <xsl:call-template name="command-body">
          <xsl:with-param name="parent-name" select="$parent-name"/>
          <xsl:with-param name="parent" select="."/>
        </xsl:call-template>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <xsl:template name="command-body">
    <xsl:param name="parent-name"/>
    <xsl:param name="parent" select="."/>
    <xsl:variable name="command-name" select="concat ($parent-name, name)"/>
    <xsl:value-of select="$command-name"/>
    <xsl:call-template name="newline"/>
    <xsl:text> = element </xsl:text>
    <xsl:value-of select="name"/>
    <xsl:call-template name="newline"/>
    <xsl:text>     {</xsl:text>
    <xsl:call-template name="newline"/>
    <xsl:for-each select="pattern">
      <xsl:call-template name="pattern">
        <xsl:with-param name="parent-name" select="concat ($command-name, '_')"/>
        <xsl:with-param name="parent" select="$parent"/>
      </xsl:call-template>
    </xsl:for-each>
    <xsl:text>     }</xsl:text>
    <xsl:call-template name="newline"/>
    <xsl:for-each select="ele">
      <xsl:call-template name="newline"/>
      <xsl:call-template name="ele">
        <xsl:with-param name="parent-name" select="concat ($command-name, '_')"/>
      </xsl:call-template>
    </xsl:for-each>
  </xsl:template>

  <!-- Responses. -->

  <xsl:template name="response-body">
    <xsl:variable name="command-name" select="concat (name, '_response')"/>
    <xsl:value-of select="$command-name"/>
    <xsl:call-template name="newline"/>
    <xsl:text> = element </xsl:text>
    <xsl:value-of select="$command-name"/>
    <xsl:call-template name="newline"/>
    <xsl:text>     {</xsl:text>
    <xsl:call-template name="newline"/>
    <xsl:for-each select="response/pattern">
      <xsl:call-template name="pattern">
        <xsl:with-param name="parent-name" select="concat ($command-name, '_')"/>
        <xsl:with-param name="parent" select="./.."/>
      </xsl:call-template>
    </xsl:for-each>
    <xsl:text>     }</xsl:text>
    <xsl:call-template name="newline"/>
    <xsl:for-each select="response/ele">
      <xsl:call-template name="newline"/>
      <xsl:call-template name="ele">
        <xsl:with-param name="parent-name" select="concat ($command-name, '_')"/>
      </xsl:call-template>
    </xsl:for-each>
  </xsl:template>

</xsl:stylesheet>

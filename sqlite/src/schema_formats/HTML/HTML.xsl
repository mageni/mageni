<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet
    version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:str="http://exslt.org/strings"
    xmlns:func = "http://exslt.org/functions"
    extension-element-prefixes="str func">
  <xsl:output method="html"
              doctype-system="http://www.w3.org/TR/html4/strict.dtd"
              doctype-public="-//W3C//DTD HTML 4.01//EN"
              encoding="UTF-8" />
  <xsl:strip-space elements="pretty"/>

<!--
Copyright (C) 2010-2019 Greenbone Networks GmbH

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

<!-- Greenbone Management Protocol (GMP) single page HTML doc generator. -->

  <xsl:variable name="rnc-comments">0</xsl:variable>
  <xsl:include href="rnc.xsl"/>

  <!-- Helpers. -->

  <xsl:template name="newline">
    <xsl:text>
</xsl:text>
  </xsl:template>

  <!-- Remove leading newlines, leaving other newlines intact. -->
  <func:function name="func:string-left-trim-nl">
    <xsl:param name="string"/>
    <xsl:choose>
      <xsl:when test="string-length($string) = 0">
        <func:result select="''"/>
      </xsl:when>
      <xsl:when test="starts-with($string,'&#10;')">
        <func:result select="func:string-left-trim-nl(substring($string,2))"/>
      </xsl:when>
      <xsl:otherwise>
        <func:result select="$string"/>
      </xsl:otherwise>
    </xsl:choose>
  </func:function>

  <!-- Remove trailing newlines, leaving other newlines intact. -->
  <func:function name="func:string-right-trim-nl">
    <xsl:param name="string"/>
    <xsl:choose>
      <xsl:when test="string-length($string) = 0">
        <func:result select="''"/>
      </xsl:when>
      <xsl:otherwise>
        <xsl:variable name="last"
                      select="substring($string, string-length($string))"/>
        <xsl:choose>
          <xsl:when test="$last = '&#10;' or $last = ' '">
            <func:result
              select="func:string-right-trim-nl(substring($string,1,string-length($string) - 1))"/>
          </xsl:when>
          <xsl:otherwise>
            <func:result select="$string"/>
          </xsl:otherwise>
        </xsl:choose>
      </xsl:otherwise>
    </xsl:choose>
  </func:function>

  <!-- Remove leading and trailing newlines, leaving other newlines
       intact. -->
  <func:function name="func:string-trim-nl">
    <xsl:param name="string"/>
    <func:result
      select="func:string-left-trim-nl(func:string-right-trim-nl($string))"/>
  </func:function>

  <xsl:template match="description">
    <xsl:choose>
      <xsl:when test="(count(*) = 0) and (string-length(normalize-space(text())) &gt; 0)">
        <p><xsl:value-of select="text()"/></p>
      </xsl:when>
      <xsl:otherwise>
        <xsl:for-each select="*">
          <xsl:choose>
            <xsl:when test="name()='p'">
              <p><xsl:value-of select="text()"/></p>
            </xsl:when>
            <xsl:when test="name()='l'">
              <p>
                <xsl:value-of select="lh"/>
                <ul>
                  <xsl:for-each select="li">
                    <li><xsl:value-of select="text()"/></li>
                  </xsl:for-each>
                </ul>
                <xsl:value-of select="lf"/>
              </p>
            </xsl:when>
          </xsl:choose>
        </xsl:for-each>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <!-- Called within a PRE. -->
  <xsl:template name="print-space">
    <xsl:param name="count">1</xsl:param>
    <xsl:text> </xsl:text>
    <xsl:if test="$count &gt; 0">
      <xsl:call-template name="print-space">
        <xsl:with-param name="count" select="$count - 1"/>
      </xsl:call-template>
    </xsl:if>
  </xsl:template>

  <!-- Called within a PRE. -->
  <xsl:template name="print-attributes">
    <xsl:param name="level">0</xsl:param>
    <xsl:variable name="indent" select="string-length(name()) + 2"/>
    <xsl:for-each select="attribute::*">
      <xsl:choose>
        <xsl:when test="position() = 1">
          <xsl:text> </xsl:text>
          <xsl:value-of select="name()"/>
          <xsl:text>="</xsl:text>
          <xsl:value-of select="."/>
          <xsl:text>"</xsl:text>
        </xsl:when>
        <xsl:otherwise>
          <xsl:call-template name="newline"/>
          <xsl:call-template name="print-space">
            <xsl:with-param name="count" select="$level * 2 + $indent"/>
          </xsl:call-template>
          <xsl:value-of select="name()"/>
          <xsl:text>="</xsl:text>
          <xsl:value-of select="."/>
          <xsl:text>"</xsl:text>
        </xsl:otherwise>
      </xsl:choose>
    </xsl:for-each>
  </xsl:template>

  <!-- Called within a PRE. -->
  <xsl:template name="pretty">
    <xsl:param name="level">0</xsl:param>
    <xsl:call-template name="print-space">
      <xsl:with-param name="count" select="$level * 2"/>
    </xsl:call-template>
    <xsl:choose>
      <xsl:when test="name()='truncated'">
        <xsl:text>...</xsl:text>
        <xsl:call-template name="newline"/>
      </xsl:when>
      <xsl:when test="(count(*) = 0) and (string-length(normalize-space(text())) = 0)">
        <xsl:text>&lt;</xsl:text>
        <xsl:value-of select="name()"/>
        <xsl:call-template name="print-attributes">
          <xsl:with-param name="level" select="$level"/>
        </xsl:call-template>
        <xsl:text>/&gt;</xsl:text>
        <xsl:call-template name="newline"/>
      </xsl:when>
      <xsl:when test="(count(*) = 0) and (string-length(text()) &lt;= 60)">
        <xsl:text>&lt;</xsl:text>
        <xsl:value-of select="name()"/>
        <xsl:call-template name="print-attributes">
          <xsl:with-param name="level" select="$level"/>
        </xsl:call-template>
        <xsl:text>&gt;</xsl:text>
        <xsl:value-of select="normalize-space(text())"/>
        <xsl:text>&lt;/</xsl:text>
        <xsl:value-of select="name()"/>
        <xsl:text>&gt;</xsl:text>
        <xsl:call-template name="newline"/>
      </xsl:when>
      <xsl:otherwise>
        <xsl:text>&lt;</xsl:text>
        <xsl:value-of select="name()"/>
        <xsl:call-template name="print-attributes">
          <xsl:with-param name="level" select="$level"/>
        </xsl:call-template>
        <xsl:text>&gt;</xsl:text>
        <xsl:call-template name="newline"/>
        <xsl:choose>
          <xsl:when test="name() = 'help_response' or name() = 'p'">
            <!-- Special case certain responses to preserve whitespace. -->
            <xsl:variable name="string" select="func:string-trim-nl(text())"/>
            <xsl:if test="string-length($string) &gt; 0">
              <xsl:value-of select="$string"/>
              <xsl:call-template name="newline"/>
            </xsl:if>
          </xsl:when>
          <xsl:otherwise>
            <xsl:if test="string-length(normalize-space(text())) &gt; 0">
              <xsl:call-template name="print-space">
                <xsl:with-param name="count" select="$level * 2 + 2"/>
              </xsl:call-template>
              <xsl:value-of select="normalize-space(text())"/>
              <xsl:call-template name="newline"/>
            </xsl:if>
          </xsl:otherwise>
        </xsl:choose>
        <xsl:for-each select="*">
          <xsl:call-template name="pretty">
            <xsl:with-param name="level" select="$level + 1"/>
          </xsl:call-template>
        </xsl:for-each>
        <xsl:call-template name="print-space">
          <xsl:with-param name="count" select="$level * 2"/>
        </xsl:call-template>
        <xsl:text>&lt;/</xsl:text>
        <xsl:value-of select="name()"/>
        <xsl:text>&gt;</xsl:text>
        <xsl:call-template name="newline"/>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <!-- RNC preamble. -->

  <xsl:template name="rnc-preamble">
    <h2 id="rnc_preamble">4 RNC Preamble</h2>
    <div style="border: 1px solid; padding:10px; width: 85%; align: center; margin-left: auto; margin-right: auto; background: #d5d5d5;">
      <pre>
        <xsl:call-template name="preamble"/>
      </pre>
    </div>
  </xsl:template>

  <!-- Types. -->

  <xsl:template match="type" mode="index">
    <tr id="index">
      <td id="index"><a href="#type_{name}"><xsl:value-of select="name"/></a></td>
      <td id="index">
        <xsl:if test="summary">
          <div style="margin-left: 15px;"><xsl:value-of select="normalize-space(summary)"/>.</div>
        </xsl:if>
      </td>
    </tr>
  </xsl:template>

  <xsl:template name="type-summary">
    <h2 id="type_summary">1 Summary of Data Types</h2>
    <table id="index">
    <xsl:apply-templates select="type" mode="index"/>
    </table>
  </xsl:template>

  <xsl:template match="type" mode="details">
    <xsl:param name="index">5.<xsl:value-of select="position()"/></xsl:param>
    <div>
      <div>
        <h3 id="type_{name}">
        <xsl:value-of select="$index"/>
        Data Type <tt><xsl:value-of select="name"/></tt></h3>
      </div>

      <xsl:if test="summary">
        <p>In short: <xsl:value-of select="normalize-space(summary)"/>.</p>
      </xsl:if>

      <xsl:apply-templates select="description"/>

      <h4><xsl:value-of select="$index"/>.1 RNC</h4>

      <div style="border: 1px solid; padding:10px; width: 85%; align: center; margin-left: auto; margin-right: auto; background: #d5d5d5;">
        <pre>
          <xsl:value-of select="name"/>
          <xsl:text> = </xsl:text>
          <xsl:call-template name="wrap">
            <xsl:with-param name="string">
              <xsl:value-of select="normalize-space (pattern)"/>
            </xsl:with-param>
          </xsl:call-template>
          <xsl:call-template name="newline"/>
        </pre>
      </div>

    </div>
  </xsl:template>

  <xsl:template name="type-details">
    <h2 id="type_details">5 Data Type Details</h2>
    <xsl:apply-templates select="type" mode="details"/>
  </xsl:template>

  <!-- Elements. -->

  <xsl:template match="element" mode="index">
    <tr id="index">
      <td id="index"><a href="#element_{name}"><xsl:value-of select="name"/></a></td>
      <td id="index">
        <xsl:if test="summary">
          <div style="margin-left: 15px;"><xsl:value-of select="normalize-space(summary)"/>.</div>
        </xsl:if>
      </td>
    </tr>
  </xsl:template>

  <xsl:template name="element-summary">
    <h2 id="element_summary">2 Summary of Elements</h2>
    <table id="index">
    <xsl:apply-templates select="element" mode="index"/>
    </table>
  </xsl:template>

  <xsl:template name="element-details">
    <h2 id="element_details">6 Element Details</h2>
    <xsl:apply-templates select="element"/>
  </xsl:template>

  <xsl:template match="element">
    <xsl:param name="index">6.<xsl:value-of select="position()"/></xsl:param>
    <div>
      <div>
        <h3 id="element_{name}">
        <xsl:value-of select="$index"/>
        Element <tt><xsl:value-of select="name"/></tt></h3>
      </div>

      <p>In short: <xsl:value-of select="normalize-space(summary)"/>.</p>

      <xsl:apply-templates select="description"/>

      <h4><xsl:value-of select="$index"/>.1 Structure</h4>

      <ul style="list-style: none">
        <li>
          <xsl:call-template name="command-structure"/>
        </li>
      </ul>

      <h4><xsl:value-of select="$index"/>.2 RNC</h4>

      <div style="border: 1px solid; padding:10px; width: 85%; align: center; margin-left: auto; margin-right: auto; background: #d5d5d5;">
        <div style="margin-left: 5%">
          <xsl:call-template name="command-relax"/>
        </div>
      </div>

    </div>
  </xsl:template>

  <!-- Commands. -->

  <xsl:template name="command-relax">
    <pre><xsl:call-template name="command-body"/></pre>
  </xsl:template>

  <xsl:template name="response-relax">
    <pre><xsl:call-template name="response-body"/></pre>
  </xsl:template>

  <xsl:template match="type" mode="element">
    <xsl:choose>
      <xsl:when test="count (alts) &gt; 0">
        <xsl:for-each select="alts/alt">
          <xsl:choose>
            <xsl:when test="following-sibling::alt and preceding-sibling::alt">
              <xsl:text>, </xsl:text>
            </xsl:when>
            <xsl:when test="count (following-sibling::alt) = 0">
              <xsl:text> or </xsl:text>
            </xsl:when>
            <xsl:otherwise>
            </xsl:otherwise>
          </xsl:choose>
          <xsl:text>"</xsl:text>
          <xsl:value-of select="."/>
          <xsl:text>"</xsl:text>
        </xsl:for-each>
      </xsl:when>
      <xsl:when test="normalize-space(text()) = 'text'">
        <xsl:text>text</xsl:text>
      </xsl:when>
      <xsl:otherwise>
        <a href="#element_{text()}"><xsl:value-of select="text()"/></a>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <xsl:template match="type">
    <xsl:choose>
      <xsl:when test="count (alts) &gt; 0">
        <xsl:for-each select="alts/alt">
          <xsl:choose>
            <xsl:when test="following-sibling::alt and preceding-sibling::alt">
              <xsl:text>, </xsl:text>
            </xsl:when>
            <xsl:when test="count (following-sibling::alt) = 0">
              <xsl:text> or </xsl:text>
            </xsl:when>
            <xsl:otherwise>
            </xsl:otherwise>
          </xsl:choose>
          <xsl:text>"</xsl:text>
          <xsl:value-of select="."/>
          <xsl:text>"</xsl:text>
        </xsl:for-each>
      </xsl:when>
      <xsl:when test="normalize-space(text()) = 'text'">
        <xsl:text>text</xsl:text>
      </xsl:when>
      <xsl:otherwise>
        <a href="#type_{text()}"><xsl:value-of select="text()"/></a>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <xsl:template name="structure-line">
    <xsl:param name="line-element"/>
    <xsl:param name="element-suffix"/>
    <xsl:choose>
      <xsl:when test="name() = 'any'">
        <xsl:for-each select="*">
          <xsl:call-template name="structure-line">
            <xsl:with-param name="line-element" select="$line-element"/>
            <xsl:with-param name="element-suffix" select="'*'"/>
          </xsl:call-template>
        </xsl:for-each>
      </xsl:when>
      <xsl:when test="name() = 'attrib'">
        <li>
          @<b><xsl:value-of select="name"/></b>
          (<xsl:apply-templates select="type"/>)
          <xsl:if test="summary">
            <xsl:value-of select="normalize-space(summary)"/>.
          </xsl:if>
          <xsl:apply-templates select="filter_keywords"/>
        </li>
      </xsl:when>
      <xsl:when test="name() = 'c'">
        <li>
          <xsl:variable name="element-name" select="text()"/>
          &lt;<b><xsl:value-of select="text()"/>&gt;</b>
          <xsl:value-of select="$element-suffix"/>
          <div style="margin-left: 15px; display: inline;">
            <a href="#command_{$element-name}"><xsl:value-of select="$element-name"/></a> command.
          </div>
        </li>
      </xsl:when>
      <xsl:when test="name() = 'r'">
        <li>
          <xsl:variable name="element-name" select="text()"/>
          &lt;<b><xsl:value-of select="text()"/>_response&gt;</b>
          <xsl:value-of select="$element-suffix"/>
          <div style="margin-left: 15px; display: inline;">
            Response to <a href="#command_{$element-name}"><xsl:value-of select="$element-name"/></a> command.
          </div>
        </li>
      </xsl:when>
      <xsl:when test="name() = 'e'">
        <li>
          <xsl:variable name="element-name" select="text()"/>
          <xsl:variable name="new-line-element"
                        select="$line-element/ele[name=$element-name]"/>
          <xsl:choose>
            <xsl:when test="$new-line-element">
              &lt;<b><xsl:value-of select="text()"/></b>&gt;
              <xsl:value-of select="$element-suffix"/>
              <xsl:if test="$new-line-element/type">
                <div style="margin-left: 15px; display: inline;">(<xsl:apply-templates select="$new-line-element/type" mode="element"/>)</div>
              </xsl:if>
              <xsl:if test="$new-line-element/summary">
                <div style="margin-left: 15px; display: inline;"><xsl:value-of select="normalize-space($new-line-element/summary)"/>.</div>
              </xsl:if>
              <ul style="list-style: none">
                <xsl:for-each select="$new-line-element/pattern/*">
                  <xsl:call-template name="structure-line">
                    <xsl:with-param name="line-element" select="$new-line-element"/>
                  </xsl:call-template>
                </xsl:for-each>
              </ul>
            </xsl:when>
            <xsl:otherwise>
              <xsl:variable name="global-element"
                            select="/protocol/element[name=$element-name]"/>
              &lt;<a href="#element_{$global-element/name}"><b><xsl:value-of select="text()"/></b></a>&gt;
              <xsl:value-of select="$element-suffix"/>
              <div style="margin-left: 15px; display: inline;"><xsl:value-of select="normalize-space($global-element/summary)"/>.</div>
            </xsl:otherwise>
          </xsl:choose>
        </li>
      </xsl:when>
      <xsl:when test="name() = 'g'">
        <li>
          <i>The group</i><b><xsl:value-of select="$element-suffix"/></b>
          <ul style="list-style: none">
            <xsl:for-each select="*">
              <xsl:call-template name="structure-line">
                <xsl:with-param name="line-element" select="$line-element"/>
              </xsl:call-template>
            </xsl:for-each>
          </ul>
        </li>
      </xsl:when>
      <xsl:when test="name() = 'o'">
        <xsl:for-each select="*">
          <xsl:call-template name="structure-line">
            <xsl:with-param name="line-element" select="$line-element"/>
            <xsl:with-param name="element-suffix" select="'?'"/>
          </xsl:call-template>
        </xsl:for-each>
      </xsl:when>
      <xsl:when test="name() = 'or'">
        <li>
          <i>One of</i><b><xsl:value-of select="$element-suffix"/></b>
          <ul style="list-style: none">
            <xsl:for-each select="*">
              <xsl:call-template name="structure-line">
                <xsl:with-param name="line-element" select="$line-element"/>
              </xsl:call-template>
            </xsl:for-each>
          </ul>
        </li>
      </xsl:when>
    </xsl:choose>
  </xsl:template>

  <xsl:template name="command-structure">
    <ul style="list-style: none">
      <xsl:choose>
        <xsl:when test="(count(pattern/*) = 0) and (string-length(normalize-space(pattern)) = 0)">
          <i>Empty single element.</i>
        </xsl:when>
        <xsl:otherwise>
          <xsl:variable name="command" select="."/>
          <xsl:for-each select="pattern/*">
            <xsl:call-template name="structure-line">
              <xsl:with-param name="line-element" select="$command"/>
            </xsl:call-template>
          </xsl:for-each>
        </xsl:otherwise>
      </xsl:choose>
    </ul>
  </xsl:template>

  <xsl:template match="command">
    <xsl:param name="index">7.<xsl:value-of select="position()"/></xsl:param>
    <div>
      <div>
        <h3 id="command_{name}">
        <xsl:value-of select="$index"/>
        Command <tt><xsl:value-of select="name"/></tt></h3>
      </div>

      <p>In short: <xsl:value-of select="normalize-space(summary)"/>.</p>

      <xsl:apply-templates select="description"/>

      <h4><xsl:value-of select="$index"/>.1 Structure</h4>

      <ul style="list-style: none">
        <li>
          <i>Command</i>
          <xsl:call-template name="command-structure"/>
        </li>
        <li style="margin-top: 15px;">
          <i>Response</i>
          <xsl:for-each select="response">
            <xsl:call-template name="command-structure"/>
          </xsl:for-each>
        </li>
      </ul>

      <h4><xsl:value-of select="$index"/>.2 RNC</h4>

      <div style="border: 1px solid; padding:10px; width: 85%; align: center; margin-left: auto; margin-right: auto; background: #d5d5d5;">
        <i>Command</i>
        <div style="margin-left: 5%">
          <xsl:call-template name="command-relax"/>
        </div>
        <i>Response</i>
        <div style="margin-left: 5%">
          <xsl:call-template name="response-relax"/>
        </div>
      </div>

      <xsl:choose>
        <xsl:when test="count(example) &gt; 0">
          <xsl:for-each select="example">
            <h4><xsl:value-of select="$index"/>.3 Example: <xsl:value-of select="summary"/></h4>
            <xsl:apply-templates select="description"/>
            <div style="margin-left: 5%; margin-right: 5%;">
              <i>Client</i>
              <div style="margin-left: 2%; margin-right: 2%;">
                <xsl:for-each select="request/*">
                  <pre>
                    <xsl:call-template name="pretty"/>
                  </pre>
                </xsl:for-each>
              </div>
              <i>Manager</i>
              <div style="margin-left: 2%; margin-right: 2%;">
                <xsl:for-each select="response/*">
                  <pre>
                    <xsl:call-template name="pretty"/>
                  </pre>
                </xsl:for-each>
              </div>
            </div>
          </xsl:for-each>
        </xsl:when>
        <xsl:otherwise>
        </xsl:otherwise>
      </xsl:choose>

    </div>
  </xsl:template>

  <xsl:template match="command" mode="index">
    <tr id="index">
      <td id="index"><a href="#command_{name}"><xsl:value-of select="name"/></a></td>
      <td id="index"><div style="margin-left: 15px;"><xsl:value-of select="normalize-space(summary)"/>.</div></td>
    </tr>
  </xsl:template>

  <xsl:template name="command-summary">
    <h2 id="command_summary">3 Summary of Commands</h2>
    <table id="index">
    <xsl:apply-templates select="command" mode="index"/>
    </table>
  </xsl:template>

  <xsl:template name="command-details">
    <h2 id="command_details">7 Command Details</h2>
    <xsl:apply-templates select="command"/>
  </xsl:template>

  <!-- Filter keywords -->
  <xsl:template match="filter_keywords">
    <div style="margin-left: 10px; padding: 0 0 3px 5px">
      <i>
        <b>Keywords</b>
        <xsl:if test="condition">
          <xsl:text> if </xsl:text>
          <xsl:value-of select="condition"/>
        </xsl:if>
      </i>
      <ul style="list-style: none; padding-left: 10px;">
        <xsl:for-each select="column|option">
          <li>
            <i>
              <xsl:value-of select="name()"/>
              <xsl:text> </xsl:text>
            </i>
            <b><xsl:value-of select="name"/></b>
            <xsl:text> (</xsl:text>
              <xsl:apply-templates select="type"/>
            <xsl:text>) </xsl:text>
            <xsl:value-of select="summary"/>
          </li>
        </xsl:for-each>
      </ul>
    </div>
  </xsl:template>

  <!-- Changes. -->

  <xsl:template match="change">
    <xsl:param name="index">8.<xsl:value-of select="position()"/></xsl:param>
    <div>
      <div>
        <h3>
          <xsl:value-of select="$index"/>
          Change in <tt><xsl:value-of select="command"/></tt>
        </h3>
      </div>

      <p>In short: <xsl:value-of select="normalize-space(summary)"/>.</p>

      <xsl:apply-templates select="description"/>
    </div>
  </xsl:template>

  <xsl:template name="changes">
    <h2 id="changes">
      8 Compatibility Changes in Version
      <xsl:value-of select="/protocol/version"/>
    </h2>
    <xsl:apply-templates select="change[version=/protocol/version]"/>
  </xsl:template>

  <!-- Deprecation Warnings. -->

  <xsl:template match="deprecation">
    <xsl:param name="index">9.<xsl:value-of select="position()"/></xsl:param>
    <div>
      <div>
        <h3>
          <xsl:value-of select="$index"/>
          Deprecation warning for <tt><xsl:value-of select="command"/></tt>
        </h3>
      </div>

      <p>In short: <xsl:value-of select="normalize-space(summary)"/>.</p>

      <xsl:apply-templates select="description"/>
    </div>
  </xsl:template>

  <xsl:template name="deprecations">
    <h2 id="deprecations">
      9 Deprecation Warnings for Version
      <xsl:value-of select="/protocol/version"/>
    </h2>
    <xsl:apply-templates select="deprecation[version=/protocol/version]"/>
  </xsl:template>

  <!-- Root. -->

  <xsl:template match="protocol">
    <html>
      <head>
        <title>
          <xsl:choose>
            <xsl:when test="abbreviation">
              <xsl:value-of select="abbreviation"/>
            </xsl:when>
            <xsl:when test="name">
              <xsl:value-of select="name"/>
            </xsl:when>
            <xsl:otherwise>
              Protocol definition
            </xsl:otherwise>
          </xsl:choose>
        </title>
      </head>
      <body style="background-color: #FFFFFF; margin: 0px; font: small Verdana, sans-serif; font-size: 12px; color: #1A1A1A;">
        <div style="width: 98%; width:700px; align: center; margin-left: auto; margin-right: auto;">
          <table style="width: 100%;" cellpadding="3" cellspacing="0">
            <tr>
              <td valign="top">
                <h1>
                  <xsl:if test="abbreviation">
                    <xsl:value-of select="abbreviation"/>:
                  </xsl:if>
                  <xsl:value-of select="name"/>
                </h1>

                <xsl:if test="version">
                  <p>Version: <xsl:value-of select="normalize-space(version)"/></p>
                </xsl:if>

                <xsl:if test="summary">
                  <p><xsl:value-of select="normalize-space(summary)"/>.</p>
                </xsl:if>

                <h2 id="contents">Contents</h2>
                <ol>
                  <li><a href="#type_summary">Summary of Data Types</a></li>
                  <li><a href="#element_summary">Summary of Elements</a></li>
                  <li><a href="#command_summary">Summary of Commands</a></li>
                  <li><a href="#rnc_preamble">RNC Preamble</a></li>
                  <li><a href="#type_details">Data Type Details</a></li>
                  <li><a href="#element_details">Element Details</a></li>
                  <li><a href="#command_details">Command Details</a></li>
                  <li>
                    <a href="#changes">
                      Compatibility Changes in Version
                      <xsl:value-of select="/protocol/version"/>
                    </a>
                  </li>
                  <li>
                    <a href="#deprecations">
                      Deprecation Warnings for Version
                      <xsl:value-of select="/protocol/version"/>
                    </a>
                  </li>
                </ol>

                <xsl:call-template name="type-summary"/>
                <xsl:call-template name="element-summary"/>
                <xsl:call-template name="command-summary"/>
                <xsl:call-template name="rnc-preamble"/>
                <xsl:call-template name="type-details"/>
                <xsl:call-template name="element-details"/>
                <xsl:call-template name="command-details"/>
                <xsl:call-template name="changes"/>
                <xsl:call-template name="deprecations"/>

                <div style="text-align: center; padding: 5px;">
                  This file was automatically generated.
                </div>
              </td>
            </tr>
          </table>
        </div>
      </body>
    </html>
  </xsl:template>

  <xsl:template match="/">
    <xsl:apply-templates select="protocol"/>
  </xsl:template>

</xsl:stylesheet>

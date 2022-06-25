<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet
    version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:str="http://exslt.org/strings"
    xmlns:func="http://exslt.org/functions"
    xmlns:date="http://exslt.org/dates-and-times"
    xmlns:openvas="http://openvas.org"
    extension-element-prefixes="str date func openvas">
  <xsl:output method="html"
              doctype-system="http://www.w3.org/TR/html4/strict.dtd"
              doctype-public="-//W3C//DTD HTML 4.01//EN"
              encoding="UTF-8" />

<!--
OpenVAS Manager
$Id$
Description: Report stylesheet for HTML format.

Authors:
Matthew Mundell <matthew.mundell@greenbone.net>

Copyright:
Copyright (C) 2010 Greenbone Networks GmbH

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

  <!-- <xsl:key name="host_results" match="*/result" use="host" /> -->
  <!-- <xsl:key name="host_ports" match="*/result[port]" use="../host" /> -->

<func:function name="openvas:timezone-abbrev">
  <xsl:choose>
    <xsl:when test="/report/@extension='xml'">
      <func:result select="/report/report/timezone_abbrev"/>
    </xsl:when>
    <xsl:otherwise>
      <func:result select="/report/timezone_abbrev"/>
    </xsl:otherwise>
  </xsl:choose>
</func:function>

<func:function name="openvas:get-nvt-tag">
  <xsl:param name="tags"/>
  <xsl:param name="name"/>
  <xsl:variable name="after">
    <xsl:value-of select="substring-after (nvt/tags, concat ($name, '='))"/>
  </xsl:variable>
  <xsl:choose>
      <xsl:when test="contains ($after, '|')">
        <func:result select="substring-before ($after, '|')"/>
      </xsl:when>
      <xsl:otherwise>
        <func:result select="$after"/>
      </xsl:otherwise>
  </xsl:choose>
</func:function>

<!-- Currently only a very simple formatting method to produce
     nice HTML from a structured text:
     - create paragraphs for each text block separated with a empty line
-->
<xsl:template name="structured-text">
  <xsl:param name="string"/>

  <xsl:for-each select="str:split($string, '&#10;&#10;')">
    <p>
      <xsl:value-of select="."/>
    </p>
  </xsl:for-each>
</xsl:template>

<xsl:template name="prognostic-description">
  <xsl:param name="string"/>

  <xsl:for-each select="str:split($string, '&#10;&#10;')">
    <p>
      <xsl:for-each select="str:split(., '&#10;')">
        <xsl:value-of select="."/>
        <br/>
      </xsl:for-each>
    </p>
  </xsl:for-each>
</xsl:template>

<xsl:template name="highlight-diff">
  <xsl:param name="string"/>

  <xsl:for-each select="str:tokenize($string, '&#10;')">
      <xsl:call-template name="highlight-diff-line">
        <xsl:with-param name="string" select="."/>
      </xsl:call-template>
  </xsl:for-each>
</xsl:template>

<!-- This is called within a PRE. -->
<xsl:template name="highlight-diff-line">
  <xsl:param name="string"/>

  <xsl:variable name="to-next-newline">
    <xsl:value-of select="substring-before($string, '&#10;')"/>
  </xsl:variable>

  <xsl:choose>
    <xsl:when test="string-length($string) = 0">
      <!-- The string is empty. -->
    </xsl:when>
    <xsl:when test="(string-length($to-next-newline) = 0) and (substring($string, 1, 1) != '&#10;')">
      <!-- A single line missing a newline, output up to the edge. -->
      <xsl:choose>
        <xsl:when test="(substring($string, 1, 1) = '@')">
<div class="diff at">
<xsl:value-of select="substring($string, 1, 90)"/>
</div>
        </xsl:when>
        <xsl:when test="(substring($string, 1, 1) = '+')">
<div class="diff plus">
<xsl:value-of select="substring($string, 1, 90)"/>
</div>
        </xsl:when>
        <xsl:when test="(substring($string, 1, 1) = '-')">
<div class="diff minus">
<xsl:value-of select="substring($string, 1, 90)"/>
</div>
        </xsl:when>
        <xsl:otherwise>
<div class="diff">
<xsl:value-of select="substring($string, 1, 90)"/>
</div>
        </xsl:otherwise>
      </xsl:choose>
      <xsl:if test="string-length($string) &gt; 90">&#8629;
<xsl:call-template name="highlight-diff-line">
  <xsl:with-param name="string" select="substring($string, 91, string-length($string))"/>
</xsl:call-template>
      </xsl:if>
    </xsl:when>
    <xsl:when test="(string-length($to-next-newline) + 1 &lt; string-length($string)) and (string-length($to-next-newline) &lt; 90)">
      <!-- There's a newline before the edge, so output the line. -->
      <xsl:choose>
        <xsl:when test="(substring($string, 1, 1) = '@')">
<div class="diff at">
<xsl:value-of select="substring($string, 1, string-length($to-next-newline) + 1)"/>
</div>
        </xsl:when>
        <xsl:when test="(substring($string, 1, 1) = '+')">
<div class="diff plus">
<xsl:value-of select="substring($string, 1, 90)"/>
</div>
        </xsl:when>
        <xsl:when test="(substring($string, 1, 1) = '-')">
<div class="diff minus">
<xsl:value-of select="substring($string, 1, 90)"/>
</div>
        </xsl:when>
        <xsl:otherwise>
<div class="diff">
<xsl:value-of select="substring($string, 1, string-length($to-next-newline) + 1)"/>
</div>
        </xsl:otherwise>
      </xsl:choose>
<xsl:call-template name="highlight-diff-line">
  <xsl:with-param name="string" select="substring($string, string-length($to-next-newline) + 2, string-length($string))"/>
</xsl:call-template>
    </xsl:when>
    <xsl:otherwise>
      <!-- Any newline comes after the edge, so output up to the edge. -->
      <xsl:choose>
        <xsl:when test="(substring($string, 1, 1) = '@')">
<div class="diff at">
<xsl:value-of select="substring($string, 1, 90)"/>
</div>
        </xsl:when>
        <xsl:when test="(substring($string, 1, 1) = '+')">
<div class="diff plus">
<xsl:value-of select="substring($string, 1, 90)"/>
</div>
        </xsl:when>
        <xsl:when test="(substring($string, 1, 1) = '-')">
<div class="diff minus">
<xsl:value-of select="substring($string, 1, 90)"/>
</div>
        </xsl:when>
        <xsl:otherwise>
<div class="diff">
<xsl:value-of select="substring($string, 1, 90)"/>
</div>
        </xsl:otherwise>
      </xsl:choose>
      <xsl:if test="string-length($string) &gt; 90">&#8629;
<xsl:call-template name="hightlight-diff-line">
  <xsl:with-param name="string" select="substring($string, 91, string-length($string))"/>
</xsl:call-template>
      </xsl:if>
    </xsl:otherwise>
  </xsl:choose>

</xsl:template>

  <xsl:template name="date">
    <xsl:param name="time" select="text ()"/>
    <xsl:value-of select="concat (date:day-abbreviation ($time), ' ', date:month-abbreviation ($time), ' ', date:day-in-month ($time), ' ', format-number(date:hour-in-day($time), '00'), ':', format-number(date:minute-in-hour($time), '00'), ':', format-number(date:second-in-minute($time), '00'), ' ', date:year($time), ' ', openvas:timezone-abbrev ())"/>
  </xsl:template>

  <xsl:template match="scan_start">
    <tr>
      <td>Scan started:</td>
      <td>
        <xsl:if test="string-length (text ())">
          <b>
            <xsl:call-template name="date"/>
          </b>
        </xsl:if>
      </td>
    </tr>
  </xsl:template>

  <xsl:template match="scan_end">
    <tr>
      <td>Scan ended:</td>
      <td>
        <xsl:if test="string-length (text ())">
          <xsl:call-template name="date"/>
        </xsl:if>
      </td>
    </tr>
  </xsl:template>

  <xsl:template match="note">
    <xsl:param name="delta">0</xsl:param>
    <xsl:choose>
      <xsl:when test="active='0'"/>
      <xsl:otherwise>
        <div class="note">
          <b>Note</b><xsl:if test="$delta and $delta &gt; 0"> (Result <xsl:value-of select="$delta"/>)</xsl:if><br/>
          <pre>
            <xsl:value-of select="text"/>
          </pre>
          <xsl:choose>
            <xsl:when test="string-length (end_time) &gt; 0">
              <xsl:text>Active until: </xsl:text>
              <xsl:call-template name="date">
                <xsl:with-param name="time" select="end_time"/>
              </xsl:call-template>
              <xsl:text>.</xsl:text>
              <br/>
            </xsl:when>
            <xsl:otherwise>
            </xsl:otherwise>
          </xsl:choose>
          <xsl:text>Last modified: </xsl:text>
          <xsl:call-template name="date">
            <xsl:with-param name="time" select="modification_time"/>
          </xsl:call-template>
          <xsl:text>.</xsl:text>
          <br/>
        </div>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <xsl:template match="override">
    <xsl:param name="delta">0</xsl:param>
    <xsl:choose>
      <xsl:when test="active='0'"/>
      <xsl:otherwise>
        <div class="override">
          <b>
            Override from
            <xsl:choose>
              <xsl:when test="string-length(threat) = 0">
                Any
              </xsl:when>
              <xsl:otherwise>
                <xsl:value-of select="threat"/>
              </xsl:otherwise>
            </xsl:choose>
            to <xsl:value-of select="new_threat"/></b><xsl:if test="$delta and $delta &gt; 0"> (Result <xsl:value-of select="$delta"/>)</xsl:if><br/>
          <pre>
            <xsl:value-of select="text"/>
          </pre>
          <xsl:choose>
            <xsl:when test="string-length (end_time) &gt; 0">
              <xsl:text>Active until: </xsl:text>
              <xsl:call-template name="date">
                <xsl:with-param name="time" select="end_time"/>
              </xsl:call-template>
              <xsl:text>.</xsl:text>
              <br/>
            </xsl:when>
            <xsl:otherwise>
            </xsl:otherwise>
          </xsl:choose>
          <xsl:text>Last modified: </xsl:text>
          <xsl:call-template name="date">
            <xsl:with-param name="time" select="modification_time"/>
          </xsl:call-template>
          <xsl:text>.</xsl:text>
        </div>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <xsl:template name="ref_cve_list">
    <xsl:param name="cvelist"/>

    <xsl:variable name="token" select="/envelope/token"/>

    <xsl:variable name="cvecount" select="count(str:split($cvelist, ','))"/>
    <xsl:if test="$cvecount &gt; 0">
      <tr valign="top">
        <td>CVE:</td>
        <td>
          <xsl:for-each select="str:split($cvelist, ',')">
            <xsl:value-of select="normalize-space(.)"/>
            <xsl:if test="position() &lt; $cvecount">
              <xsl:text>, </xsl:text>
            </xsl:if>
          </xsl:for-each>
        </td>
      </tr>
    </xsl:if>
  </xsl:template>

  <xsl:template name="ref_bid_list">
    <xsl:param name="bidlist"/>

    <xsl:variable name="token" select="/envelope/token"/>

    <xsl:variable name="bidcount" select="count(str:split($bidlist, ','))"/>
    <xsl:if test="$bidcount &gt; 0">
      <tr valign="top">
        <td>BID:</td>
        <td>
          <xsl:for-each select="str:split($bidlist, ',')">
            <xsl:value-of select="."/>
            <xsl:if test="position() &lt; $bidcount">
              <xsl:text>, </xsl:text>
            </xsl:if>
          </xsl:for-each>
        </td>
      </tr>
    </xsl:if>
  </xsl:template>

  <xsl:template name="ref_cert_list">
    <xsl:param name="certlist"/>
    <xsl:variable name="token" select="/envelope/token"/>
    <xsl:variable name="certcount" select="count($certlist/cert_ref)"/>

    <xsl:if test="count($certlist/warning)">
      <xsl:for-each select="$certlist/warning">
        <tr valign="top">
          <td>CERT:</td>
          <td><i>Warning: <xsl:value-of select="text()"/></i></td>
        </tr>
      </xsl:for-each>
    </xsl:if>

    <xsl:if test="$certcount &gt; 0">
      <tr valign="top">
        <td>CERT:</td>
        <td>
          <xsl:for-each select="$certlist/cert_ref">
            <xsl:value-of select="@id"/>
            <xsl:if test="position() &lt; $certcount">
              <xsl:text>, </xsl:text>
            </xsl:if>
          </xsl:for-each>
        </td>
      </tr>
    </xsl:if>
  </xsl:template>

  <xsl:template name="ref_xref_list">
    <xsl:param name="xreflist"/>

    <xsl:variable name="token" select="/envelope/token"/>

    <xsl:variable name="xrefcount" select="count(str:split($xreflist, ','))"/>
    <xsl:if test="$xrefcount &gt; 0">
      <xsl:for-each select="str:split($xreflist, ',')">
        <tr valign="top">
          <td><xsl:if test="position()=1">Other:</xsl:if></td>
          <xsl:choose>
            <xsl:when test="contains(., 'URL:')">
              <td><xsl:value-of select="substring-after(., 'URL:')"/></td>
            </xsl:when>
            <xsl:otherwise>
              <td><xsl:value-of select="."/></td>
            </xsl:otherwise>
          </xsl:choose>
        </tr>
      </xsl:for-each>
    </xsl:if>
  </xsl:template>

  <xsl:template match="result" mode="issue">
    <xsl:param name="report" select="/report"/>

    <xsl:variable name="threat_class">
      <xsl:choose>
         <xsl:when test="threat='Low'">low</xsl:when>
         <xsl:when test="threat='Medium'">medium</xsl:when>
         <xsl:when test="threat='High'">high</xsl:when>
         <xsl:otherwise></xsl:otherwise>
      </xsl:choose>
    </xsl:variable>

    <xsl:choose>
      <xsl:when test="$report/@type = 'prognostic'">
        <div class="result_head {$threat_class}">
          <div class="location_float">
            <xsl:value-of select="cve/cpe/@id"/>
          </div>
          <b><xsl:value-of select="threat"/></b>
          <xsl:if test="string-length(cve/cvss_base) &gt; 0">
             (CVSS: <xsl:value-of select="cve/cvss_base"/>)
          </xsl:if>
          <div><xsl:value-of select="cve/@id"/></div>
        </div>
        <div class="result_section">
          <xsl:call-template name="prognostic-description">
            <xsl:with-param name="string" select="description"/>
          </xsl:call-template>
        </div>
      </xsl:when>
      <xsl:otherwise>
        <div class="result_head {$threat_class}">
          <div class="location_float">
            <xsl:value-of select="port"/>
          </div>
          <xsl:if test="delta/text()">
            <div class="delta_float">
              <xsl:choose>
                <xsl:when test="delta/text() = 'changed'">~</xsl:when>
                <xsl:when test="delta/text() = 'gone'">&#8722;</xsl:when>
                <xsl:when test="delta/text() = 'new'">+</xsl:when>
                <xsl:when test="delta/text() = 'same'">=</xsl:when>
              </xsl:choose>
            </div>
          </xsl:if>
          <b><xsl:value-of select="threat"/></b>
          <xsl:choose>
            <xsl:when test="original_threat">
              <xsl:choose>
                <xsl:when test="threat = original_threat">
                  <xsl:if test="string-length(nvt/cvss_base) &gt; 0">
                     (CVSS: <xsl:value-of select="nvt/cvss_base"/>)
                  </xsl:if>
                </xsl:when>
                <xsl:otherwise>
                  (Overridden from <b><xsl:value-of select="original_threat"/></b>)
                </xsl:otherwise>
              </xsl:choose>
            </xsl:when>
            <xsl:otherwise>
              <xsl:if test="string-length(nvt/cvss_base) &gt; 0">
                 (CVSS: <xsl:value-of select="nvt/cvss_base"/>)
              </xsl:if>
            </xsl:otherwise>
          </xsl:choose>
          <div class="full_width">
            NVT:
            <xsl:variable name="max" select="80"/>
              <xsl:choose>
                <xsl:when test="string-length(nvt/name) &gt; $max">
                  <xsl:value-of select="substring(nvt/name, 0, $max)"/>...
                </xsl:when>
                <xsl:otherwise>
                  <xsl:value-of select="nvt/name"/>
                </xsl:otherwise>
              </xsl:choose>
            (OID: <xsl:value-of select="nvt/@oid"/>)
          </div>
        </div>
        <xsl:if test="count (detection)">
          <div class="result_section">
            Product detection result:
            <xsl:value-of select="detection/result/details/detail[name = 'product']/value/text()"/>
            by
            <xsl:value-of select="detection/result/details/detail[name = 'source_name']/value/text()"/>
            (OID: <xsl:value-of select="detection/result/details/detail[name = 'source_oid']/value/text()"/>)
          </div>
        </xsl:if>

        <!-- Summary -->
        <xsl:if test="string-length (openvas:get-nvt-tag (nvt/tags, 'summary')) &gt; 0">
          <div class="result_section">
            <b>Summary</b>
            <xsl:call-template name="structured-text">
              <xsl:with-param name="string"
                              select="openvas:get-nvt-tag (nvt/tags, 'summary')"/>
            </xsl:call-template>
          </div>
        </xsl:if>

        <!-- Result -->
        <xsl:choose>
          <xsl:when test="$report/@type = 'prognostic'">
            <div class="result_section">
              <xsl:choose>
                <xsl:when test="delta/text() = 'changed'">
                  <b>Result 1</b>
                  <p></p>
                </xsl:when>
              </xsl:choose>
              <p>
                <xsl:call-template name="prognostic-description">
                  <xsl:with-param name="string" select="description"/>
                </xsl:call-template>
              </p>
            </div>
          </xsl:when>
          <xsl:otherwise>
            <div class="result_section">
              <xsl:choose>
                <xsl:when test="delta/text() = 'changed'">
                  <b>Result 1</b>
                  <p></p>
                </xsl:when>
              </xsl:choose>
              <b>Vulnerability Detection Result</b>
              <xsl:choose>
                <xsl:when test="string-length(description) &lt; 2">
                  <p>
                    Vulnerability was detected according to the Vulnerability Detection Method.
                  </p>
                </xsl:when>
                <xsl:otherwise>
                  <pre>
                    <xsl:value-of select="description"/>
                  </pre>
                </xsl:otherwise>
              </xsl:choose>
            </div>
          </xsl:otherwise>
        </xsl:choose>

        <xsl:if test="string-length (openvas:get-nvt-tag (nvt/tags, 'impact')) &gt; 0 and openvas:get-nvt-tag (nvt/tags, 'impact') != 'N/A'">
          <div class="result_section">
            <b>Impact</b>
            <xsl:call-template name="structured-text">
              <xsl:with-param name="string" select="openvas:get-nvt-tag (nvt/tags, 'impact')"/>
            </xsl:call-template>
          </div>
        </xsl:if>

        <xsl:if test="(string-length (openvas:get-nvt-tag (nvt/tags, 'solution')) &gt; 0 and openvas:get-nvt-tag (nvt/tags, 'solution') != 'N/A') or (string-length (openvas:get-nvt-tag (nvt/tags, 'solution_type')) &gt; 0)">
          <div class="result_section">
          <b>Solution</b>
            <xsl:if test="string-length (openvas:get-nvt-tag (nvt/tags, 'solution_type')) &gt; 0">
              <p><b>Solution type: </b> <xsl:value-of select="openvas:get-nvt-tag (nvt/tags, 'solution_type')"/></p>
            </xsl:if>
            <xsl:call-template name="structured-text">
              <xsl:with-param name="string" select="openvas:get-nvt-tag (nvt/tags, 'solution')"/>
            </xsl:call-template>
          </div>
        </xsl:if>

        <xsl:if test="string-length (openvas:get-nvt-tag (nvt/tags, 'affected')) &gt; 0 and openvas:get-nvt-tag (nvt/tags, 'affected') != 'N/A'">
          <div class="result_section">
            <b>Affected Software/OS</b>
            <xsl:call-template name="structured-text">
              <xsl:with-param name="string" select="openvas:get-nvt-tag (nvt/tags, 'affected')"/>
            </xsl:call-template>
          </div>
        </xsl:if>

        <xsl:if test="string-length (openvas:get-nvt-tag (nvt/tags, 'insight')) &gt; 0 and openvas:get-nvt-tag (nvt/tags, 'insight') != 'N/A'">
          <div class="result_section">
            <b>Vulnerability Insight</b>
            <xsl:call-template name="structured-text">
              <xsl:with-param name="string" select="openvas:get-nvt-tag (nvt/tags, 'insight')"/>
            </xsl:call-template>
          </div>
        </xsl:if>

        <div class="result_section">
          <xsl:choose>
            <xsl:when test="(nvt/cvss_base &gt; 0) or (cve/cvss_base &gt; 0)">
              <b>Vulnerability Detection Method</b>
            </xsl:when>
            <xsl:otherwise>
              <b>Log Method</b>
            </xsl:otherwise>
          </xsl:choose>
          <xsl:call-template name="structured-text">
            <xsl:with-param name="string" select="openvas:get-nvt-tag (nvt/tags, 'vuldetect')"/>
          </xsl:call-template>
          <p>
            Details:
            <xsl:choose>
              <xsl:when test="$report/@type = 'prognostic'">
                <xsl:value-of select="normalize-space(cve/@id)"/>
              </xsl:when>
              <xsl:when test="nvt/@oid = 0">
                <xsl:if test="delta/text()">
                  <br/>
                </xsl:if>
              </xsl:when>
              <xsl:otherwise>
                <xsl:variable name="max" select="80"/>
                <xsl:choose>
                  <xsl:when test="string-length(nvt/name) &gt; $max">
                    <abbr title="{nvt/name} ({nvt/@oid})"><xsl:value-of select="substring(nvt/name, 0, $max)"/>...</abbr>
                  </xsl:when>
                  <xsl:otherwise>
                    <xsl:value-of select="nvt/name"/>
                  </xsl:otherwise>
                </xsl:choose>
                (OID: <xsl:value-of select="nvt/@oid"/>)
              </xsl:otherwise>
            </xsl:choose>
          </p>
          <xsl:choose>
            <xsl:when test="not($report/@type = 'prognostic')">
              <xsl:if test="scan_nvt_version != ''">
                <p>
                  Version used: <xsl:value-of select="scan_nvt_version"/>
                </p>
              </xsl:if>
            </xsl:when>
          </xsl:choose>
        </div>

        <xsl:if test="count (detection)">
          <div class="result_section">
            <b>Product Detection Result</b>
            <p>
              <table>
                <tr>
                  <td>Product:</td>
                  <td>
                    <xsl:value-of select="detection/result/details/detail[name = 'product']/value/text()"/>
                  </td>
                </tr>
                <tr>
                  <td>Method:</td>
                  <td>
                    <xsl:value-of select="detection/result/details/detail[name = 'source_name']/value/text()"/>
                    (OID: <xsl:value-of select="detection/result/details/detail[name = 'source_oid']/value/text()"/>)
                  </td>
                </tr>
              </table>
            </p>
          </div>
        </xsl:if>

        <xsl:variable name="cve_ref">
          <xsl:if test="nvt/cve != '' and nvt/cve != 'NOCVE'">
            <xsl:value-of select="nvt/cve/text()"/>
          </xsl:if>
        </xsl:variable>
        <xsl:variable name="bid_ref">
          <xsl:if test="nvt/bid != '' and nvt/bid != 'NOBID'">
            <xsl:value-of select="nvt/bid/text()"/>
          </xsl:if>
        </xsl:variable>
        <xsl:variable name="cert_ref" select="nvt/cert"/>
        <xsl:variable name="xref">
          <xsl:if test="nvt/xref != '' and nvt/xref != 'NOXREF'">
            <xsl:value-of select="nvt/xref/text()"/>
          </xsl:if>
        </xsl:variable>

        <xsl:if test="$cve_ref != '' or $bid_ref != '' or $xref != '' or count($cert_ref/cert_ref) > 0">
          <div class="result_section">
            <b>References</b><br/>
            <p>
              <table>
                <xsl:call-template name="ref_cve_list">
                  <xsl:with-param name="cvelist" select="$cve_ref"/>
                </xsl:call-template>
                <xsl:call-template name="ref_bid_list">
                  <xsl:with-param name="bidlist" select="$bid_ref"/>
                </xsl:call-template>
                <xsl:call-template name="ref_cert_list">
                  <xsl:with-param name="certlist" select="$cert_ref"/>
                </xsl:call-template>
                <xsl:call-template name="ref_xref_list">
                  <xsl:with-param name="xreflist" select="$xref"/>
                </xsl:call-template>
              </table>
            </p>
          </div>
        </xsl:if>

        <xsl:if test="delta">
          <xsl:choose>
            <xsl:when test="delta/text() = 'changed'">
              <div class="result_section">
                <b>Result 2</b>
                <pre>
                  <xsl:value-of select="delta/result/description"/>
                </pre>
              </div>
              <div class="result_section">
                <b>Different Lines</b>
                <p>
                  <xsl:call-template name="highlight-diff">
                    <xsl:with-param name="string" select="delta/diff"/>
                  </xsl:call-template>
                </p>
              </div>
            </xsl:when>
          </xsl:choose>
        </xsl:if>
        <xsl:variable name="delta">
          <xsl:choose>
            <xsl:when test="delta">1</xsl:when>
            <xsl:otherwise>0</xsl:otherwise>
          </xsl:choose>
        </xsl:variable>
        <xsl:apply-templates select="notes/note">
          <xsl:with-param name="delta" select="$delta"/>
        </xsl:apply-templates>
        <xsl:apply-templates select="delta/notes/note">
          <xsl:with-param name="delta" select="2"/>
        </xsl:apply-templates>
        <xsl:if test="$report/filters/keywords/keyword[column='apply_overrides']/value='1'">
          <xsl:apply-templates select="overrides/override">
            <xsl:with-param name="delta" select="$delta"/>
          </xsl:apply-templates>
          <xsl:apply-templates select="delta/overrides/override">
            <xsl:with-param name="delta" select="2"/>
          </xsl:apply-templates>
        </xsl:if>
      </xsl:otherwise>
    </xsl:choose>

  </xsl:template>

  <xsl:template name="auth-success-row">
    <xsl:variable name="host" select="host"/>
    <xsl:for-each select="/report/host[ip=$host]/detail[name='Auth-SSH-Success']">
      <tr>
        <td>
          <xsl:value-of select="$host"/>
          <xsl:choose>
            <xsl:when test="string-length(/report/host[ip=$host]/detail[name='hostname']/value) &gt; 0">
              <xsl:text> (</xsl:text>
              <xsl:value-of select="/report/host[ip=$host]/detail[name='hostname']/value/text()"/>
              <xsl:text>)</xsl:text>
            </xsl:when>
          </xsl:choose>
        </td>
        <td>
          <xsl:text>SSH</xsl:text>
        </td>
        <td>
          <xsl:text>Success</xsl:text>
        </td>
        <td>
          <xsl:value-of select="value/text()"/>
        </td>
      </tr>
    </xsl:for-each>
    <xsl:for-each select="/report/host[ip=$host]/detail[name='Auth-SSH-Failure']">
      <tr>
        <td>
          <xsl:value-of select="$host"/>
          <xsl:choose>
            <xsl:when test="string-length(/report/host[ip=$host]/detail[name='hostname']/value) &gt; 0">
              <xsl:text> (</xsl:text>
              <xsl:value-of select="/report/host[ip=$host]/detail[name='hostname']/value/text()"/>
              <xsl:text>)</xsl:text>
            </xsl:when>
          </xsl:choose>
        </td>
        <td>
          <xsl:text>SSH</xsl:text>
        </td>
        <td>
          <xsl:text>Failure</xsl:text>
        </td>
        <td>
          <xsl:value-of select="value/text()"/>
        </td>
      </tr>
    </xsl:for-each>
    <xsl:for-each select="/report/host[ip=$host]/detail[name='Auth-SMB-Success']">
      <tr>
        <td>
          <xsl:value-of select="$host"/>
          <xsl:choose>
            <xsl:when test="string-length(/report/host[ip=$host]/detail[name='hostname']/value) &gt; 0">
              <xsl:text> (</xsl:text>
              <xsl:value-of select="/report/host[ip=$host]/detail[name='hostname']/value/text()"/>
              <xsl:text>)</xsl:text>
            </xsl:when>
          </xsl:choose>
        </td>
        <td>
          <xsl:text>SMB</xsl:text>
        </td>
        <td>
          <xsl:text>Success</xsl:text>
        </td>
        <td>
          <xsl:value-of select="value/text()"/>
        </td>
      </tr>
    </xsl:for-each>
    <xsl:for-each select="/report/host[ip=$host]/detail[name='Auth-SMB-Failure']">
      <tr>
        <td>
          <xsl:value-of select="$host"/>
          <xsl:choose>
            <xsl:when test="string-length(/report/host[ip=$host]/detail[name='hostname']/value) &gt; 0">
              <xsl:text> (</xsl:text>
              <xsl:value-of select="/report/host[ip=$host]/detail[name='hostname']/value/text()"/>
              <xsl:text>)</xsl:text>
            </xsl:when>
          </xsl:choose>
        </td>
        <td>
          <xsl:text>SMB</xsl:text>
        </td>
        <td>
          <xsl:text>Failure</xsl:text>
        </td>
        <td>
          <xsl:value-of select="value/text()"/>
        </td>
      </tr>
    </xsl:for-each>
    <xsl:for-each select="/report/host[ip=$host]/detail[name='Auth-ESXi-Success']">
      <tr>
        <td>
          <xsl:value-of select="$host"/>
          <xsl:choose>
            <xsl:when test="string-length(/report/host[ip=$host]/detail[name='hostname']/value) &gt; 0">
              <xsl:text> (</xsl:text>
              <xsl:value-of select="/report/host[ip=$host]/detail[name='hostname']/value/text()"/>
              <xsl:text>)</xsl:text>
            </xsl:when>
          </xsl:choose>
        </td>
        <td>
          <xsl:text>ESXi</xsl:text>
        </td>
        <td>
          <xsl:text>Success</xsl:text>
        </td>
        <td>
          <xsl:value-of select="value/text()"/>
        </td>
      </tr>
    </xsl:for-each>
    <xsl:for-each select="/report/host[ip=$host]/detail[name='Auth-ESXi-Failure']">
      <tr>
        <td>
          <xsl:value-of select="$host"/>
          <xsl:choose>
            <xsl:when test="string-length(/report/host[ip=$host]/detail[name='hostname']/value) &gt; 0">
              <xsl:text> (</xsl:text>
              <xsl:value-of select="/report/host[ip=$host]/detail[name='hostname']/value/text()"/>
              <xsl:text>)</xsl:text>
            </xsl:when>
          </xsl:choose>
        </td>
        <td>
          <xsl:text>ESXi</xsl:text>
        </td>
        <td>
          <xsl:text>Failure</xsl:text>
        </td>
        <td>
          <xsl:value-of select="value/text()"/>
        </td>
      </tr>
    </xsl:for-each>
  </xsl:template>

  <xsl:template match="report">
    <xsl:choose>
      <xsl:when test="@extension='xml'">
        <xsl:apply-templates select="report"/>
      </xsl:when>
      <xsl:otherwise>
        <xsl:call-template name="real-report"/>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <xsl:template name="real-report">
    <xsl:choose>
      <xsl:when test="delta">
        <h1>Delta Report Summary</h1>

        <p>
          This document compares the results of two security scans.
          The report first summarises the hosts found.  Then, for each host,
          the report describes the changes that occurred between the two
          scans.
        </p>
      </xsl:when>
      <xsl:when test="@type = 'prognostic'">
        <h1>Prognostic Report Summary</h1>

        <p>
          This document predicts the results of a security scan, based on
          scan information already gathered for the hosts.
          The report first summarises the results found.  Then, for each host,
          the report describes every issue found.  Please consider the
          advice given in each description, in order to rectify the issue.
        </p>
      </xsl:when>
      <xsl:otherwise>
        <h1>Summary</h1>

        <p>
          This document reports on the results of an automatic security scan.
          The report first summarises the results found.  Then, for each host,
          the report describes every issue found.  Please consider the
          advice given in each description, in order to rectify the issue.
        </p>
      </xsl:otherwise>
    </xsl:choose>

    <xsl:choose>
      <xsl:when test="@type = 'prognostic'">
      </xsl:when>
      <xsl:otherwise>
        <p>
          <xsl:choose>
            <xsl:when test="filters/keywords/keyword[column='autofp']/value='1'">
              Vendor security updates are trusted, using full CVE matching.
            </xsl:when>
            <xsl:when test="filters/keywords/keyword[column='autofp']/value='2'">
              Vendor security updates are trusted, using partial CVE matching.
            </xsl:when>
            <xsl:otherwise>
              Vendor security updates are not trusted.
            </xsl:otherwise>
          </xsl:choose>
        </p>

        <p>
          <xsl:choose>
            <xsl:when test="filters/keywords/keyword[column='apply_overrides']/value='1'">
              Overrides are on.  When a result has an override, this report uses the threat of the override.
            </xsl:when>
            <xsl:otherwise>
              Overrides are off.  Even when a result has an override, this report uses the actual threat of the result.
            </xsl:otherwise>
          </xsl:choose>
        </p>

        <p>
          <xsl:choose>
            <xsl:when test="filters/keywords/keyword[column='overrides']/value = 0">
              Information on overrides is excluded from the report.
            </xsl:when>
            <xsl:otherwise>
              Information on overrides is included in the report.
            </xsl:otherwise>
          </xsl:choose>
        </p>

        <p>
          <xsl:choose>
            <xsl:when test="filters/keywords/keyword[column='notes']/value = 0">
              Notes are excluded from the report.
            </xsl:when>
            <xsl:otherwise>
              Notes are included in the report.
            </xsl:otherwise>
          </xsl:choose>
        </p>
      </xsl:otherwise>
    </xsl:choose>

    <p>
      This report might not show details of all issues that were found.
      <xsl:if test="filters/keywords/keyword[column='result_hosts_only']/value = 1">
        It only lists hosts that produced issues.
      </xsl:if>
      <xsl:if test="string-length(filters/phrase) &gt; 0">
        It shows issues that contain the search phrase "<xsl:value-of select="filters/phrase"/>".
      </xsl:if>
      <xsl:if test="contains(filters/keywords/keyword[column='levels']/value, 'h') = false">
        Issues with the threat level "High" are not shown.
      </xsl:if>
      <xsl:if test="contains(filters/keywords/keyword[column='levels']/value, 'm') = false">
        Issues with the threat level "Medium" are not shown.
      </xsl:if>
      <xsl:if test="contains(filters/keywords/keyword[column='levels']/value, 'l') = false">
        Issues with the threat level "Low" are not shown.
      </xsl:if>
      <xsl:if test="contains(filters/keywords/keyword[column='levels']/value, 'g') = false">
        Issues with the threat level "Log" are not shown.
      </xsl:if>
      <xsl:if test="contains(filters/keywords/keyword[column='levels']/value, 'd') = false">
        Issues with the threat level "Debug" are not shown.
      </xsl:if>
      <xsl:if test="contains(filters/keywords/keyword[column='levels']/value, 'f') = false">
        Issues with the threat level "False Positive" are not shown.
      </xsl:if>
      <xsl:choose>
        <xsl:when test="filters/keywords/keyword[column='min_qod']/value = 0">
        </xsl:when>
        <xsl:when test="string-length (filters/keywords/keyword[column='min_qod']/value) > 0">
          <xsl:text>Only results with a minimum QoD of </xsl:text>
          <xsl:value-of select="filters/keywords/keyword[column='min_qod']/value"/>
          <xsl:text> are shown. </xsl:text>
        </xsl:when>
        <xsl:otherwise>
          <xsl:text>Only results with a minimum QoD of 70 are shown.</xsl:text>
        </xsl:otherwise>
      </xsl:choose>
    </p>

    <p>
      <xsl:variable name="last" select="results/@start + count(results/result) - 1"/>
      <xsl:choose>
        <xsl:when test="$last = 0">
          <xsl:text>This report contains 0 results.</xsl:text>
        </xsl:when>
        <xsl:when test="$last = results/@start">
          <xsl:text>This report contains result </xsl:text>
          <xsl:value-of select="$last"/>
          <xsl:text> of the </xsl:text>
          <xsl:value-of select="result_count/filtered"/>
          <xsl:text> results selected by the</xsl:text>
          <xsl:text> filtering above.</xsl:text>
        </xsl:when>
        <xsl:when test="$last = result_count/filtered">
          <xsl:text>This report contains all </xsl:text>
          <xsl:value-of select="result_count/filtered"/>
          <xsl:text> results selected by the</xsl:text>
          <xsl:text> filtering described above.</xsl:text>
        </xsl:when>
        <xsl:otherwise>
          <xsl:text>This report contains results </xsl:text>
          <xsl:value-of select="results/@start"/>
          <xsl:text> to </xsl:text>
          <xsl:value-of select="$last"/>
          <xsl:text> of the </xsl:text>
          <xsl:value-of select="result_count/filtered"/>
          <xsl:text> results selected by the</xsl:text>
          <xsl:text> filtering described above.</xsl:text>
        </xsl:otherwise>
      </xsl:choose>
      <xsl:choose>
        <xsl:when test="@type = 'prognostic'">
        </xsl:when>
        <xsl:when test="delta">
        </xsl:when>
        <xsl:otherwise>
          <xsl:text>  Before filtering there were </xsl:text>
          <xsl:value-of select="result_count/text()"/>
          <xsl:text> results.</xsl:text>
        </xsl:otherwise>
      </xsl:choose>
    </p>
    <p>
      <xsl:text>All dates are displayed using the timezone "</xsl:text>
      <xsl:value-of select="timezone"/>
      <xsl:text>", which is abbreviated "</xsl:text>
      <xsl:value-of select="timezone_abbrev"/>
      <xsl:text>".</xsl:text>
    </p>

    <xsl:choose>
      <xsl:when test="delta">
        <table>
          <tr>
            <td>Scan 1 started:</td>
            <td><xsl:value-of select="scan_start"/></td>
          </tr>
          <tr>
            <td>Scan 2 started:</td>
            <td><xsl:value-of select="delta/report/scan_start"/></td>
          </tr>
        </table>
        <table>
          <tr>
            <td>Scan 1 ended:</td>
            <td><xsl:value-of select="scan_end"/></td>
          </tr>
          <tr>
            <td>Scan 2 ended:</td>
            <td><xsl:value-of select="delta/report/scan_end"/></td>
          </tr>
          <tr>
            <td>Task:</td>
            <td><xsl:value-of select="task/name"/></td>
          </tr>
        </table>
      </xsl:when>
      <xsl:otherwise>
        <table>
          <xsl:apply-templates select="scan_start" />
          <xsl:apply-templates select="scan_end" />
          <tr>
            <td>Task:</td>
            <td><xsl:value-of select="task/name"/></td>
          </tr>
        </table>
      </xsl:otherwise>
    </xsl:choose>

    <h2>Host Summary</h2>

    <table width="100%">
      <tr class="table_head">
        <td>Host</td>
        <td>Start</td>
        <td>End</td>
        <td>High</td>
        <td>Medium</td>
        <td>Low</td>
        <td>Log</td>
        <td>False Positive</td>
      </tr>
      <xsl:for-each select="host" >
        <xsl:variable name="current_host" select="ip" />
        <tr>
          <td>
            <xsl:variable name="hostname" select="detail[name/text() = 'hostname']/value"/>
            <xsl:choose>
              <xsl:when test="$hostname">
                <a href="#{$current_host}"><xsl:value-of select="concat($current_host, ' (', $hostname, ')')"/></a>
              </xsl:when>
              <xsl:otherwise>
                <a href="#{$current_host}"><xsl:value-of select="$current_host"/></a>
              </xsl:otherwise>
            </xsl:choose>
          </td>
          <td>
            <xsl:value-of select="concat (date:month-abbreviation(start/text()), ' ', date:day-in-month(start/text()), ', ', format-number(date:hour-in-day(start/text()), '00'), ':', format-number(date:minute-in-hour(start/text()), '00'), ':', format-number(date:second-in-minute(start/text()), '00'))"/>
          </td>
          <td>
            <xsl:choose>
              <xsl:when test="end/text() != ''">
                <xsl:value-of select="concat (date:month-abbreviation(end/text()), ' ', date:day-in-month(end/text()), ', ', format-number(date:hour-in-day(end/text()), '00'), ':', format-number(date:minute-in-hour(end/text()), '00'), ':', format-number(date:second-in-minute(end/text()), '00'))"/>
              </xsl:when>
              <xsl:otherwise>(not finished)</xsl:otherwise>
            </xsl:choose>
          </td>
          <td><xsl:value-of select="count(../results/result[host/text() = $current_host][threat/text() = 'High'])"/></td>
          <td><xsl:value-of select="count(../results/result[host/text() = $current_host][threat/text() = 'Medium'])"/></td>
          <td><xsl:value-of select="count(../results/result[host/text() = $current_host][threat/text() = 'Low'])"/></td>
          <td><xsl:value-of select="count(../results/result[host/text() = $current_host][threat/text() = 'Log'])"/></td>
          <td><xsl:value-of select="count(../results/result[host/text() = $current_host][threat/text() = 'False Positive'])"/></td>
        </tr>
      </xsl:for-each>
      <tr>
        <td>Total: <xsl:value-of select="count(host_start)"/></td>
        <td></td>
        <td></td>
        <td><xsl:value-of select="count(results/result[threat/text() = 'High'])"/></td>
        <td><xsl:value-of select="count(results/result[threat/text() = 'Medium'])"/></td>
        <td><xsl:value-of select="count(results/result[threat/text() = 'Low'])"/></td>
        <td><xsl:value-of select="count(results/result[threat/text() = 'Log'])"/></td>
        <td><xsl:value-of select="count(results/result[threat/text() = 'False Positive'])"/></td>
      </tr>
    </table>

   <xsl:choose>
     <xsl:when test="string-length(/report/host/detail[name='Auth-SSH-Success']/value) &gt; 0 or
       string-length(/report/host/detail[name='Auth-SSH-Failure']/value) &gt; 0 or
       string-length(/report/host/detail[name='Auth-SMB-Success']/value) &gt; 0 or
       string-length(/report/host/detail[name='Auth-SMB-Failure']/value) &gt; 0 or
       string-length(/report/host/detail[name='Auth-ESXi-Success']/value) &gt; 0 or
       string-length(/report/host/detail[name='Auth-ESXi-Failure']/value) &gt; 0">
       <h2>Host Authentications</h2>
       <table>
         <tr class="table_head">
           <td>Host</td>
           <td>Protocol</td>
           <td>Result</td>
           <td>Port/User</td>
         </tr>
         <xsl:for-each select="host_start">
           <xsl:sort select="key('host-by-ip', host)/detail[name='hostname']/value/text()"/>
           <xsl:call-template name="auth-success-row"/>
         </xsl:for-each>
       </table>
      </xsl:when>
    </xsl:choose>

    <h1>Results per Host</h1>

    <xsl:variable name="report" select="." />
    <xsl:for-each select="host" >
      <xsl:variable name="current_host" select="ip" />

      <h2 id="{$current_host}">Host <xsl:value-of select="$current_host"/></h2>
      <table>
        <xsl:choose>
          <xsl:when test="$report/@type = 'prognostic'">
          </xsl:when>
          <xsl:otherwise>
            <tr>
              <td>Scanning of this host started at:</td>
              <td>
                <xsl:call-template name="date">
                  <xsl:with-param name="time" select="start"/>
                </xsl:call-template>
              </td>
            </tr>
          </xsl:otherwise>
        </xsl:choose>
        <tr>
          <td>Number of results:</td>
          <td>
            <xsl:value-of select="count(../results/result[host/text()=$current_host])"/>
          </td>
        </tr>
      <!-- Number of results: <xsl:value-of select="count(key('host_results', $current_host))"/> -->
      </table>

      <xsl:variable name="cves" select="str:split(detail[name = 'Closed CVEs']/value, ',')"/>
      <xsl:choose>
        <xsl:when test="$report/@type = 'delta'">
        </xsl:when>
        <xsl:when test="$report/filters/keywords/keyword[column='show_closed_cves']/value = 1">
          <h2>
            CVEs closed by vendor security updates for <xsl:value-of select="$current_host"/>
          </h2>
          <table class="gbntable" cellspacing="2" cellpadding="4">
            <tr class="table_head">
              <td>CVE</td>
              <td>NVT</td>
            </tr>
            <xsl:variable name="host" select="."/>
            <xsl:for-each select="$cves">
              <tr>
                <td>
                  <xsl:variable name="token" select="/envelope/token"/>
                  <xsl:value-of select="."/>
                </td>
                <td>
                  <xsl:variable name="cve" select="normalize-space(.)"/>
                  <xsl:variable name="closed_cve"
                                select="$host/detail[name = 'Closed CVE' and contains(value, $cve)]"/>
                  <xsl:value-of select="$closed_cve/source/description"/>
                </td>
              </tr>
            </xsl:for-each>
          </table>
        </xsl:when>
      </xsl:choose>

      <xsl:choose>
        <xsl:when test="$report/@type = 'prognostic'">
        </xsl:when>
        <xsl:otherwise>
          <h3>Port Summary for Host <xsl:value-of select="$current_host" /></h3>

          <table width="100%">
            <tr class="table_head">
              <td>Service (Port)</td>
              <td>Threat Level</td>
            </tr>

            <xsl:for-each select="../ports/port[host=$current_host]">
              <tr>
                <td><xsl:value-of select="text()"/></td>
                <td><xsl:value-of select="threat"/></td>
              </tr>
            </xsl:for-each>

          <!-- <xsl:apply-templates select="key('host_results', $current_host)" mode="FIX"/> -->

          </table>
        </xsl:otherwise>
      </xsl:choose>

      <h3>Security Issues for Host <xsl:value-of select="$current_host" /></h3>

      <xsl:apply-templates select="../results/result[host/text()=$current_host]" mode="issue">
        <xsl:with-param name="report" select="$report"/>
      </xsl:apply-templates>

    </xsl:for-each>

  </xsl:template>

  <xsl:template match="/">
    <html>
      <head>
        <style>
body {
  background-color: #FFFFFF;
  margin: 0px;
  font: small Verdana, sans-serif;
  font-size: 12px;
  color: #1A1A1A;
}

div.content {
  width: 98%;
  align: center;
  margin-left: auto;
  margin-right: auto;
}

tr.table_head {
  background-color: #d5d5d5;
}

.diff {
  white-space: pre;
  font-family: monospace;
}

.diff.at {
  color: #9932CC;
}

.diff.plus {
  color: #006400;
}

.diff.minus {
  color: #B22222;
}

div.footer {
  text-align: center;
}

div.note, div.override {
  padding:4px;
  margin:3px;
  margin-bottom:0px;
  margin-top:0px;
  border: 1px solid #CCCCCC;
  border-top: 0px;
  background-color: #ffff90;
}

.result_head {
  padding:4px;
  margin:3px;
  margin-bottom:0px;
  color: #FFFFFF;
  border: 1px solid #CCCCCC;
  border-bottom: 0px;
  background:#d5d5d5;
}

.result_head.low {
  background:#539dcb
}

.result_head.medium {
  background:#f99f31
}

.result_head.high {
  background:#cb1d17
}

.result_section {
  padding:4px;
  margin:3px;
  margin-bottom:0px;
  margin-top:0px;
  border: 1px solid #CCCCCC;
  border-top: 0px;
}

.location_float {
  float: right;
  text-align:right;
}

.delta_float {
  float: left;
  font-size: 24px;
  border: 2px;
  padding-left: 2px;
  padding-right: 8px;
  margin:0px;
}

.full_width {
  width: 100%;
}

pre {
 white-space: pre-wrap;
 word-wrap: break-word;
}
        </style>
        <title>Scan Report</title>
      </head>
      <body>
        <div class="content">
                <xsl:apply-templates/>
                <div class="footer">
                  This file was automatically generated.
                </div>
        </div>
      </body>
    </html>
  </xsl:template>

</xsl:stylesheet>

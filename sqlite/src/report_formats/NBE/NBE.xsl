<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet
    version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:func="http://exslt.org/functions"
    xmlns:str="http://exslt.org/strings"
    xmlns:date="http://exslt.org/dates-and-times"
    xmlns:openvas="http://openvas.org"
    extension-element-prefixes="str date func openvas">
  <xsl:output method="text" encoding="string" indent="no"/>
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

<!-- Report stylesheet for NBE format. -->

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

  <xsl:template name="newline">
    <xsl:text>
</xsl:text>
  </xsl:template>

  <xsl:template name="ctime">
    <xsl:param name="date" select="text()"/>
    <xsl:choose>
      <xsl:when test="string-length ($date) &gt; 0">
        <xsl:value-of select="concat (date:day-abbreviation ($date), ' ', date:month-abbreviation ($date), ' ', date:day-in-month ($date), ' ', format-number(date:hour-in-day($date), '00'), ':', format-number(date:minute-in-hour($date), '00'), ':', format-number(date:second-in-minute($date), '00'), ' ', date:year($date))"/>
      </xsl:when>
    </xsl:choose>
  </xsl:template>

  <xsl:template name="substring-before-last">
    <xsl:param name="string"/>
    <xsl:param name="delimiter"/>

    <xsl:if test="$string != '' and $delimiter != ''">
      <xsl:variable name="head" select="substring-before($string, $delimiter)"/>
      <xsl:variable name="tail" select="substring-after($string, $delimiter)"/>
      <xsl:value-of select="$head"/>
      <xsl:if test="contains($tail, $delimiter)">
        <xsl:value-of select="$delimiter"/>
        <xsl:call-template name="substring-before-last">
          <xsl:with-param name="string" select="$tail"/>
          <xsl:with-param name="delimiter" select="$delimiter"/>
        </xsl:call-template>
      </xsl:if>
    </xsl:if>
  </xsl:template>

<xsl:template match="scan_start">
  <xsl:text>timestamps|||scan_start|</xsl:text>
  <xsl:call-template name="ctime"/>
  <xsl:text>|</xsl:text>
  <xsl:call-template name="newline"/>
</xsl:template>

<xsl:template match="scan_end">
  <xsl:text>timestamps|||scan_end|</xsl:text>
  <xsl:call-template name="ctime"/>
  <xsl:text>|</xsl:text>
  <xsl:call-template name="newline"/>
</xsl:template>

<xsl:template match="threat">
  <xsl:choose>
    <xsl:when test="text()='Low'">Security Note</xsl:when>
    <xsl:when test="text()='Medium'">Security Warning</xsl:when>
    <xsl:when test="text()='High'">Security Hole</xsl:when>
    <xsl:otherwise>Log Message</xsl:otherwise>
  </xsl:choose>
</xsl:template>

<xsl:template match="nvt/tags">
  <xsl:value-of select="substring-after('.', 'cvss_base_vector=')"/>
</xsl:template>

<xsl:template name="ref_cve_list">
  <xsl:param name="cvelist"/>

  <xsl:variable name="cvecount" select="count(str:split($cvelist, ','))"/>
  <xsl:if test="$cvecount &gt; 0">
    <xsl:text>CVE: </xsl:text>
    <xsl:for-each select="str:split($cvelist, ',')">
      <xsl:value-of select="str:replace (normalize-space(.), '&#10;', '\n')"/>
      <xsl:if test="position() &lt; $cvecount">
        <xsl:text>, </xsl:text>
      </xsl:if>
    </xsl:for-each>
    <xsl:text>\n</xsl:text>
  </xsl:if>
</xsl:template>

<xsl:template name="ref_bid_list">
  <xsl:param name="bidlist"/>

  <xsl:variable name="bidcount" select="count(str:split($bidlist, ','))"/>
  <xsl:if test="$bidcount &gt; 0">
    <xsl:text>BID: </xsl:text>
    <xsl:for-each select="str:split($bidlist, ',')">
      <xsl:value-of select="str:replace (., '&#10;', '\n')"/>
      <xsl:if test="position() &lt; $bidcount">
        <xsl:text>, </xsl:text>
      </xsl:if>
    </xsl:for-each>
    <xsl:text>\n</xsl:text>
  </xsl:if>
</xsl:template>

<xsl:template name="ref_cert_list">
  <xsl:param name="certlist"/>

  <xsl:variable name="certcount" select="count($certlist/cert_ref)"/>

  <xsl:if test="count($certlist/warning)">
    <xsl:for-each select="$certlist/warning">
      <xsl:text>CERT: Warning: </xsl:text>
      <xsl:value-of select="str:replace (text(), '&#10;', '\n')"/>
      <xsl:text>\n</xsl:text>
    </xsl:for-each>
  </xsl:if>

  <xsl:if test="$certcount &gt; 0">
    <xsl:text>CERT: </xsl:text>
    <xsl:for-each select="$certlist/cert_ref">
      <xsl:value-of select="@id"/>
      <xsl:if test="position() &lt; $certcount">
        <xsl:text>, </xsl:text>
      </xsl:if>
    </xsl:for-each>
    <xsl:text>\n</xsl:text>
  </xsl:if>
</xsl:template>

<xsl:template name="ref_xref_list">
  <xsl:param name="xreflist"/>

  <xsl:variable name="xrefcount" select="count(str:split($xreflist, ','))"/>
  <xsl:if test="$xrefcount &gt; 0">
    <xsl:for-each select="str:split($xreflist, ',')">
      <xsl:if test="position()=1">
        <xsl:text>Other:</xsl:text>
        <xsl:text>\n</xsl:text>
      </xsl:if>
      <xsl:text>    </xsl:text>
      <xsl:choose>
        <xsl:when test="contains(., 'URL:')">
          <xsl:value-of select="str:replace (substring-after(., 'URL:'), '&#10;', '\n')"/>
        </xsl:when>
        <xsl:otherwise>
          <xsl:value-of select="str:replace (., '&#10;', '\n')"/>
        </xsl:otherwise>
      </xsl:choose>
      <xsl:text>\n</xsl:text>
    </xsl:for-each>
  </xsl:if>
</xsl:template>

<xsl:template match="result">
  <xsl:variable name="netmask">
    <xsl:call-template name="substring-before-last">
      <xsl:with-param name="string" select="host/text()"/>
      <xsl:with-param name="delimiter" select="'.'"/>
    </xsl:call-template>
  </xsl:variable>
  <xsl:variable name="report" select="../.." />

  <xsl:text>results</xsl:text>
  <xsl:text>|</xsl:text>
  <xsl:value-of select="$netmask"/>
  <xsl:text>|</xsl:text>
  <xsl:value-of select="host/text()"/>
  <xsl:text>|</xsl:text>
  <xsl:value-of select="port"/>
  <xsl:text>|</xsl:text>
  <xsl:value-of select="str:replace(nvt/@oid, '1.3.6.1.4.1.25623.1.0.', '')"/>
  <xsl:text>|</xsl:text>
  <xsl:apply-templates select="threat"/>
  <xsl:text>|</xsl:text>

  <!-- Summary -->
  <xsl:if test="string-length (openvas:get-nvt-tag (nvt/tags, 'summary')) &gt; 0">
    <xsl:text>Summary:</xsl:text>
    <xsl:text>\n</xsl:text>
    <xsl:value-of select="str:replace (openvas:get-nvt-tag (nvt/tags, 'summary'), '&#10;', '\n')"/>
    <xsl:text>\n\n</xsl:text>
  </xsl:if>

  <!-- Result -->
  <xsl:choose>
    <xsl:when test="delta/text() = 'changed'">
      <xsl:text>Result 1:</xsl:text>
      <xsl:text>\n</xsl:text>
    </xsl:when>
  </xsl:choose>
  <xsl:text>Vulnerability Detection Result:</xsl:text>
  <xsl:text>\n</xsl:text>
  <xsl:choose>
    <xsl:when test="string-length(description) &lt; 2">
      <xsl:text>Vulnerability was detected according to the Vulnerability Detection Method.</xsl:text>
    </xsl:when>
    <xsl:otherwise>
      <xsl:value-of select="str:replace (description, '&#10;', '\n')"/>
    </xsl:otherwise>
  </xsl:choose>
  <xsl:text>\n</xsl:text>

  <xsl:if test="string-length (openvas:get-nvt-tag (nvt/tags, 'impact')) &gt; 0 and openvas:get-nvt-tag (nvt/tags, 'impact') != 'N/A'">
    <xsl:text>Impact:</xsl:text>
    <xsl:text>\n</xsl:text>
    <xsl:value-of select="str:replace (openvas:get-nvt-tag (nvt/tags, 'impact'), '&#10;', '\n')"/>
    <xsl:text>\n\n</xsl:text>
  </xsl:if>

  <xsl:if test="(string-length (openvas:get-nvt-tag (nvt/tags, 'solution')) &gt; 0 and openvas:get-nvt-tag (nvt/tags, 'solution') != 'N/A') or (string-length (openvas:get-nvt-tag (nvt/tags, 'solution_type')))">
    <xsl:text>Solution:</xsl:text>
    <xsl:text>\n</xsl:text>
    <xsl:if test="string-length (openvas:get-nvt-tag (nvt/tags, 'solution_type')) &gt; 0">
      <xsl:text>Solution type: </xsl:text>
      <xsl:value-of select="openvas:get-nvt-tag (nvt/tags, 'solution_type')"/>
      <xsl:text>\n</xsl:text>
    </xsl:if>
    <xsl:value-of select="str:replace (openvas:get-nvt-tag (nvt/tags, 'solution'), '&#10;', '\n')"/>
    <xsl:text>\n\n</xsl:text>
  </xsl:if>

  <xsl:if test="string-length (openvas:get-nvt-tag (nvt/tags, 'affected')) &gt; 0 and openvas:get-nvt-tag (nvt/tags, 'affected') != 'N/A'">
    <xsl:text>Affected Software/OS:</xsl:text>
    <xsl:text>\n</xsl:text>
    <xsl:value-of select="str:replace (openvas:get-nvt-tag (nvt/tags, 'affected'), '&#10;', '\n')"/>
    <xsl:text>\n\n</xsl:text>
  </xsl:if>

  <xsl:if test="string-length (openvas:get-nvt-tag (nvt/tags, 'insight')) &gt; 0 and openvas:get-nvt-tag (nvt/tags, 'insight') != 'N/A'">
    <xsl:text>Vulnerability Insight:</xsl:text>
    <xsl:text>\n</xsl:text>
    <xsl:value-of select="str:replace (openvas:get-nvt-tag (nvt/tags, 'insight'), '&#10;', '\n')"/>
    <xsl:text>\n\n</xsl:text>
  </xsl:if>

  <xsl:choose>
    <xsl:when test="(nvt/cvss_base &gt; 0) or (cve/cvss_base &gt; 0)">
      <xsl:text>Vulnerability Detection Method:</xsl:text>
    </xsl:when>
    <xsl:otherwise>
      <xsl:text>Log Method:</xsl:text>
    </xsl:otherwise>
  </xsl:choose>
  <xsl:text>\n</xsl:text>
  <xsl:if test="string-length (openvas:get-nvt-tag (nvt/tags, 'vuldetect')) &gt; 0">
    <xsl:value-of select="str:replace (openvas:get-nvt-tag (nvt/tags, 'vuldetect'), '&#10;', '\n')"/>
    <xsl:text>\n</xsl:text>
  </xsl:if>
  <xsl:text>Details:</xsl:text>
  <xsl:text>\n</xsl:text>
  <xsl:choose>
    <xsl:when test="nvt/@oid = 0">
      <xsl:if test="delta/text()">
        <xsl:text>\n</xsl:text>
      </xsl:if>
    </xsl:when>
    <xsl:otherwise>
      <xsl:variable name="max" select="77"/>
      <xsl:choose>
        <xsl:when test="string-length(nvt/name) &gt; $max">
          <xsl:value-of select="substring (nvt/name, 0, $max)"/>...
        </xsl:when>
        <xsl:otherwise>
          <xsl:value-of select="nvt/name"/>
        </xsl:otherwise>
      </xsl:choose>
      <xsl:text>\n</xsl:text>
      <xsl:text>(OID: </xsl:text>
      <xsl:value-of select="nvt/@oid"/>
      <xsl:text>)</xsl:text>
    </xsl:otherwise>
  </xsl:choose>
  <xsl:text>\n</xsl:text>
  <xsl:if test="scan_nvt_version != ''">
    <xsl:text>Version used: </xsl:text>
    <xsl:value-of select="scan_nvt_version"/>
    <xsl:text>\n</xsl:text>
  </xsl:if>
  <xsl:text>\n</xsl:text>

  <xsl:if test="count (detection)">
    <xsl:text>Product Detection Result:</xsl:text>
    <xsl:text>\n</xsl:text>
    <xsl:text>Product: </xsl:text>
    <xsl:value-of select="detection/result/details/detail[name = 'product']/value/text()"/>
    <xsl:text>\n</xsl:text>
    <xsl:text>Method:</xsl:text>
    <xsl:value-of select="detection/result/details/detail[name = 'source_name']/value/text()"/>
    <xsl:text>\n</xsl:text>
    <xsl:text>(OID: </xsl:text>
    <xsl:value-of select="detection/result/details/detail[name = 'source_oid']/value/text()"/>
    <xsl:text>)</xsl:text>
    <xsl:text>\n</xsl:text>
    <xsl:text>\n</xsl:text>
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

  <xsl:if test="nvt/cvss_base != ''">
    <xsl:variable name="cvss_base_vector">
      <xsl:for-each select="str:split (nvt/tags, '|')">
        <xsl:if test="'cvss_base_vector' = substring-before (., '=')">
          <xsl:value-of select="substring-after (., '=')"/>
        </xsl:if>
      </xsl:for-each>
    </xsl:variable>

    <xsl:text>CVSS Base Score: </xsl:text>
    <xsl:value-of select="nvt/cvss_base"/>
    <xsl:text>\n(CVSS2#: </xsl:text>
    <xsl:value-of select="$cvss_base_vector"/>
    <xsl:text>)\n</xsl:text>
  </xsl:if>

  <xsl:if test="$cve_ref != '' or $bid_ref != '' or $xref != '' or count($cert_ref/cert_ref) > 0">
    <xsl:text>References:</xsl:text>
    <xsl:text>\n</xsl:text>
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
  </xsl:if>
  <xsl:call-template name="newline"/>
</xsl:template>

<xsl:template match="report">
  <xsl:apply-templates select="scan_start"/>
  <xsl:for-each select="host">
    <xsl:variable name="host"><xsl:value-of select="ip/text()"/></xsl:variable>

    <xsl:text>timestamps||</xsl:text>
    <xsl:value-of select="$host"/>
    <xsl:text>|host_start|</xsl:text>
    <xsl:call-template name="ctime">
      <xsl:with-param name="date" select="start/text()"/>
    </xsl:call-template>
    <xsl:text>|</xsl:text>
    <xsl:call-template name="newline"/>

    <xsl:apply-templates select="../results/result[host/text()=$host]"/>

    <xsl:text>timestamps||</xsl:text>
    <xsl:value-of select="$host"/>
    <xsl:text>|host_end|</xsl:text>
    <xsl:call-template name="ctime">
      <xsl:with-param name="date" select="end/text()"/>
    </xsl:call-template>
    <xsl:text>|</xsl:text>
    <xsl:call-template name="newline"/>
  </xsl:for-each>
  <!-- TODO Was start, end, start, end... in 1.0. -->
  <xsl:apply-templates select="scan_end"/>
</xsl:template>

<xsl:template match="/">
  <xsl:choose>
    <xsl:when test = "report/@extension = 'xml'">
      <xsl:apply-templates select="report/report"/>
    </xsl:when>
    <xsl:otherwise>
      <xsl:apply-templates select="report"/>
    </xsl:otherwise>
  </xsl:choose>
</xsl:template>

</xsl:stylesheet>

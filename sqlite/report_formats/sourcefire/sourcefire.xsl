<?xml version="1.0"?>
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

<!-- Sourcefire Export Stylesheet -->

<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:output method="text"
            encoding="string"/>

<!-- PORT FROM PORT ELEMENT
  Example inputs are:
  https (443/tcp)
  nfs (2049/udp)
  general/tcp
  Note however that these formats are conventions only and
  not enforced by GVM.
-->
<xsl:template name="portport">
  <xsl:variable name="before_slash" select="substring-before(port, '/')" />
  <xsl:variable name="port_nr" select="substring-after($before_slash, '(')" />
  <xsl:choose>
    <xsl:when test="string-length($port_nr) > 0">
      <xsl:value-of select="$port_nr"/>
    </xsl:when>
    <xsl:otherwise>
      <xsl:value-of select="$before_slash"/>
    </xsl:otherwise>
  </xsl:choose>
</xsl:template>

<!-- PROTOCOL FROM PORT ELEMENT
  Example inputs are:
  https (443/tcp)
  nfs (2049/udp)
  general/tcp
  Note however that these formats are conventions only and
  not enforced by GVM.
-->
<xsl:template name="portproto">
  <xsl:variable name="after_slash" select="substring-after(port, '/')" />
  <xsl:variable name="port_proto" select="substring-before($after_slash, ')')" />
  <xsl:choose>
    <xsl:when test="string-length($port_proto) > 0">
      <xsl:value-of select="$port_proto"/>
    </xsl:when>
    <xsl:otherwise>
      <xsl:value-of select="$after_slash"/>
    </xsl:otherwise>
  </xsl:choose>
</xsl:template>

<!-- DESCRIPTION TEXT, DOUBLE QUOTES REPLACED BY SINGLE QUOTES
<xsl:template name="quote_replace_recurse">
  <xsl:param name="string_to_quote"/>
  <xsl:when test="contains($string_to_quote, '\"')">
  </xsl:when>
</xsl:template>-->

<!-- MATCH RESULT -->
<!-- Create AddScanResults entries. The syntax is:
AddScanResult, ipaddr, 'scanner_id', vuln_id, port, protocol, 'name', 'description', cve_ids, bugtraq_ids
where
  vuln_id: Valid RNA vulnerability IDs, or mapped third-party vulnerability IDs.
  proto: tcp|udp
!-->
<xsl:template match="result">
AddScanResult,<xsl:value-of select="host"/>,"GVM",<xsl:value-of select="nvt/@oid"/>,<xsl:call-template name="portport" select="port"/>,<xsl:call-template name="portproto" select="port"/>,"<xsl:value-of select="nvt/name"/>","<xsl:value-of select="translate(description, '&quot;&#10;', &quot;' &quot;)"/>","cve_ids: <xsl:value-of select="translate(nvt/cve, ',', '')"/>","bugtraq_ids: <xsl:value-of select="translate(nvt/bid, ',', '')"/>"</xsl:template>

<!-- MATCH HOST -->
<xsl:template match="host">
AddHost,<xsl:value-of select="ip"/>
</xsl:template>

<!-- MATCH SCAN_START -->
<xsl:template match="scan_start">
</xsl:template>

<!-- MATCH SCAN_END -->
<xsl:template match="scan_end">
</xsl:template>

<!-- MATCH RESULT_COUNT -->
<xsl:template match="result_count">
</xsl:template>

<!-- MATCH PORTS -->
<xsl:template match="ports">
</xsl:template>

<!-- MATCH TASK -->
<xsl:template match="task">
</xsl:template>

<!-- MATCH SCAN_RUN_STATUS -->
<xsl:template match="scan_run_status">
</xsl:template>

<!-- MATCH FILTER -->
<xsl:template match="filters">
</xsl:template>

<!-- MATCH SORT -->
<xsl:template match="sort">
</xsl:template>

<!-- MATCH RESULTS -->
<xsl:template match="results">
  <xsl:apply-templates/>
</xsl:template>

<!-- MATCH REPORT -->
<!-- the following lines are intentionally not indented because
     empty lines with spaces will trouble the Sourcefire
     host input importer. -->
<xsl:template match="report"># Sourcefire Host Input File
SetSource,GVM
<xsl:apply-templates select="host"/>
<xsl:apply-templates select="results"/>
</xsl:template>

<xsl:template match="/">
  <xsl:choose>
    <xsl:when test="report/@extension='xml'">
      <xsl:apply-templates select="report/report"/>
    </xsl:when>
    <xsl:otherwise>
      <xsl:apply-templates select="report"/>
    </xsl:otherwise>
  </xsl:choose>
</xsl:template>

</xsl:stylesheet>

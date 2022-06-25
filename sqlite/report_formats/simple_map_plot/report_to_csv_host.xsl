<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet
  version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:output method = "text" indent = "no" />
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

<!-- Stylesheet for generating a list of IPs with threat summary -->

<xsl:template match="report">
IP, high, medium, low, color
127.0.0.1, 0, 0, 0, white
  <xsl:for-each select="host" >
    <xsl:variable name="current_host" select="ip"/>
    <xsl:variable name="high_count" select="count (../results/result[host/text() = $current_host][threat/text() = 'High'])"/>
    <xsl:variable name="med_count" select="count (../results/result[host/text() = $current_host][threat/text() = 'Medium'])"/>
    <xsl:variable name="low_count" select="count (../results/result[host/text() = $current_host][threat/text() = 'Low'])"/>
    <xsl:choose>
      <xsl:when test="count(../results/result[host/text() = $current_host][threat/text() = 'High']) &gt; 0">
<xsl:value-of select="$current_host"/>, <xsl:value-of select="$high_count"/>, <xsl:value-of select="$med_count"/>, <xsl:value-of select="$low_count"/>, red
      </xsl:when>
      <xsl:otherwise>
        <xsl:choose>
          <xsl:when test="count(../results/result[host/text() = $current_host][threat/text() = 'Medium']) &gt; 0">
<xsl:value-of select="normalize-space($current_host)"/>, <xsl:value-of select="$high_count"/>, <xsl:value-of select="$med_count"/>, <xsl:value-of select="$low_count"/>, orange
          </xsl:when>
          <xsl:otherwise>
            <xsl:choose>
              <xsl:when test="count(../results/result[host/text() = $current_host][threat/text() = 'Low']) &gt; 0">
<xsl:value-of select="$current_host"/>, <xsl:value-of select="$high_count"/>, <xsl:value-of select="$med_count"/>, <xsl:value-of select="$low_count"/>, blue
              </xsl:when>
            </xsl:choose>
          </xsl:otherwise>
        </xsl:choose>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:for-each>
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

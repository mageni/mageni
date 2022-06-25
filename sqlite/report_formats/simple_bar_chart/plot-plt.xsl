<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet
    version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:str="http://exslt.org/strings"
    exclude-result-prefixes="str">

  <xsl:output method="text" encoding="string" indent="no" />
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

<!-- Stylesheet for generating results per threat code for Gnuplot. -->

  <xsl:template name="newline">
    <xsl:text>
</xsl:text>
  </xsl:template>

<xsl:template match="report">
  <xsl:text>unset title</xsl:text>
  <xsl:call-template name="newline"/>
  <xsl:choose>
    <xsl:when test="report/report_format/param[name='Key'] and report/report_format/param[name='Key']/value = '0'">
      <xsl:text>unset key</xsl:text>
    </xsl:when>
    <xsl:otherwise>
      <xsl:text>set key on outside below</xsl:text>
    </xsl:otherwise>
  </xsl:choose>
  <xsl:call-template name="newline"/>
  <xsl:text>set terminal png size </xsl:text>
  <xsl:choose>
    <xsl:when test="report/report_format/param[name='Width']">
      <xsl:value-of select="report/report_format/param[name='Width']/value"/>
    </xsl:when>
    <xsl:otherwise>
      <xsl:text>400</xsl:text>
    </xsl:otherwise>
  </xsl:choose>
  <xsl:text>,</xsl:text>
  <xsl:choose>
    <xsl:when test="report/report_format/param[name='Height']">
      <xsl:value-of select="report/report_format/param[name='Height']/value"/>
    </xsl:when>
    <xsl:otherwise>
      <xsl:text>400</xsl:text>
    </xsl:otherwise>
  </xsl:choose>
  <xsl:call-template name="newline"/>
set boxwidth 0.9 relative
<xsl:choose>
  <xsl:when test="report/report_format/param[name='Fill Style']/value = 'pattern'">
    <xsl:text>set style fill pattern 2</xsl:text>
  </xsl:when>
  <xsl:when test="report/report_format/param[name='Fill Style']/value = 'solid'">
    <xsl:text>set style fill solid</xsl:text>
  </xsl:when>
  <xsl:when test="report/report_format/param[name='Fill Style']/value = 'empty'">
    <xsl:text>set style fill empty</xsl:text>
  </xsl:when>
  <xsl:otherwise>
    <xsl:text>set style fill empty</xsl:text>
  </xsl:otherwise>
</xsl:choose>
set xlabel "Threat"
set ylabel "Results"
  <xsl:choose>
    <xsl:when test="report/report_format/param[name='Height']">
      <xsl:text>set title "</xsl:text>
      <xsl:value-of select="report/report_format/param[name='Title']/value"/>
      <xsl:text>"</xsl:text>
    </xsl:when>
    <xsl:otherwise>
      <xsl:text>set title "Results per Threat"</xsl:text>
    </xsl:otherwise>
  </xsl:choose>
  <xsl:call-template name="newline"/>
show title
set border 11
set xtics nomirror
<xsl:if test="string-length (report/report_format/param[name='Blurb']/value) &gt; 0">
set label "<xsl:value-of select="str:replace (report/report_format/param[name='Blurb']/value, '&#10;', '\n')"/>" at graph 0.5,0.5 center front
</xsl:if>
show label
plot [-0.5:3.5] [0:] 'plot.dat' using 2:xticlabels(1) with boxes linetype 3 fs
exit
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

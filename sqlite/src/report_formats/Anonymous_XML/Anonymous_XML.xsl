<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet
    version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:exslt="http://exslt.org/common"
    xmlns:str="http://exslt.org/strings"
    xmlns:func="http://exslt.org/functions"
    xmlns:date="http://exslt.org/dates-and-times"
    xmlns:openvas="http://openvas.org"
    extension-element-prefixes="str date func openvas exslt">
  <xsl:output method="xml"
              indent="yes"
              encoding="UTF-8" />

<!--
Copyright (C) 2015-2018 Greenbone Networks GmbH

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

<!-- Report stylesheet for Anonymous XML format. -->

  <xsl:variable name="hosts" select="//host[not (.=preceding::host) and not (. = '')]"/>

  <xsl:variable name="all-hostnames" select="//host/detail[name = 'hostname' and not (value = '')]"/>
  <xsl:variable name="hostnames">
    <xsl:for-each select="$all-hostnames">
      <xsl:variable name="value" select="value" />
      <xsl:if test="generate-id() = generate-id($all-hostnames[value = $value][1])">
        <xsl:copy-of select="value" />
      </xsl:if>
    </xsl:for-each>
  </xsl:variable>

  <func:function name="openvas:host">
    <xsl:param name="host"/>
    <xsl:for-each select="$hosts">
      <xsl:if test=". = $host">
        <func:result select="concat (127 + round (position () div (256 * 256 * 256)), '.', round (position () div (256 * 256)), '.', round (position () div 256), '.', position () mod 256)"/>
      </xsl:if>
    </xsl:for-each>
  </func:function>

  <func:function name="openvas:hostname">
    <xsl:param name="hostname"/>
    <xsl:for-each select="exslt:node-set ($hostnames)">
      <xsl:if test=". = $hostname">
        <func:result select="concat ('host', position (), '.example.com')"/>
      </xsl:if>
    </xsl:for-each>
  </func:function>

  <xsl:template match="result/description" >
  </xsl:template>

  <xsl:template match="host" >
    <xsl:copy>
      <xsl:value-of select="openvas:host (text ())"/>
      <xsl:apply-templates select="*|@*" />
    </xsl:copy>
  </xsl:template>

  <xsl:template match="host/detail[name = 'hostname']/value" >
    <xsl:copy>
      <xsl:value-of select="openvas:hostname (text ())"/>
    </xsl:copy>
  </xsl:template>

  <xsl:template match="host/ip" >
    <xsl:copy>
      <xsl:value-of select="openvas:host (text ())"/>
    </xsl:copy>
  </xsl:template>

  <xsl:template match="host/detail[name = 'traceroute']" >
  </xsl:template>

  <xsl:template match="host/detail[name = 'MAC']" >
  </xsl:template>

  <xsl:template match="host/detail[substring (name, 1, 4) = 'MAC-']" >
  </xsl:template>

  <xsl:template match="host/detail[substring (name, 1, 5) = 'Cert:']" >
  </xsl:template>

  <xsl:template match="host/detail[substring (name, 1, 11) = 'SSLDetails:']" >
  </xsl:template>

  <xsl:template match="host/detail[name = 'SSLInfo']" >
  </xsl:template>

  <xsl:template match="results/result/owner">
  </xsl:template>

  <xsl:template match="task/name">
  </xsl:template>

  <xsl:template match="scan/task/slave/name">
  </xsl:template>

  <xsl:template match="node()|@*" >
    <xsl:copy>
      <xsl:apply-templates select="node()|@*" />
    </xsl:copy>
  </xsl:template>

</xsl:stylesheet>

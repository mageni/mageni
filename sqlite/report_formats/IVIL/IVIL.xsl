<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:str="http://exslt.org/strings" extension-element-prefixes="str">
<xsl:output method="xml" doctype-system="" doctype-public="" encoding="UTF-8" />

<!--
GVM
$Id$
Description: Report stylesheet for IVIL format.

Authors:
Tim Brown <timb@openvas.org>

Copyright:
Copyright (C) 2010 Tim Brown

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License version 2,
or, at your option, any later version as published by the Free
Software Foundation

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
-->

<xsl:template match="report/@id">
	<xsl:apply-templates />
</xsl:template>

<xsl:template match="report/scan_end">
	<xsl:value-of select="substring(., 21, 4)"/>
	<xsl:choose>
		<xsl:when test="contains(., 'Jan')">01</xsl:when>
		<xsl:when test="contains(., 'Feb')">02</xsl:when>
		<xsl:when test="contains(., 'Mar')">03</xsl:when>
		<xsl:when test="contains(., 'Apr')">04</xsl:when>
		<xsl:when test="contains(., 'May')">05</xsl:when>
		<xsl:when test="contains(., 'Jun')">06</xsl:when>
		<xsl:when test="contains(., 'Jul')">07</xsl:when>
		<xsl:when test="contains(., 'Aug')">08</xsl:when>
		<xsl:when test="contains(., 'Sep')">09</xsl:when>
		<xsl:when test="contains(., 'Oct')">10</xsl:when>
		<xsl:when test="contains(., 'Nov')">11</xsl:when>
		<xsl:when test="contains(., 'Dec')">12</xsl:when>
	</xsl:choose>
	<xsl:choose>
		<xsl:when test="substring(., 9, 2)=' 1'">01</xsl:when>
		<xsl:when test="substring(., 9, 2)=' 2'">02</xsl:when>
		<xsl:when test="substring(., 9, 2)=' 3'">03</xsl:when>
		<xsl:when test="substring(., 9, 2)=' 4'">04</xsl:when>
		<xsl:when test="substring(., 9, 2)=' 5'">05</xsl:when>
		<xsl:when test="substring(., 9, 2)=' 6'">06</xsl:when>
		<xsl:when test="substring(., 9, 2)=' 7'">07</xsl:when>
		<xsl:when test="substring(., 9, 2)=' 8'">08</xsl:when>
		<xsl:when test="substring(., 9, 2)=' 9'">09</xsl:when>
		<xsl:otherwise><xsl:value-of select="substring(., 9, 2)"/></xsl:otherwise>
	</xsl:choose>
	<xsl:value-of select="substring(., 12, 2)"/>
	<xsl:value-of select="substring(., 15, 2)"/>
	<xsl:value-of select="substring(., 18, 2)"/>
</xsl:template>

<xsl:template match="report/results" mode="version">
	<xsl:for-each select="result">
		<xsl:if test="nvt/name='Information about the scan'">
			<xsl:value-of select="substring-before(substring-after(description, 'GVM version : '), '.&#10;')" />
		</xsl:if>
	</xsl:for-each>
</xsl:template>

<xsl:template match="report/results" mode="findings">
	<xsl:for-each select="result">
		<finding>
			<ip><xsl:value-of select="host" /></ip>
			<port><xsl:value-of select="port" /></port>
			<id><xsl:value-of select="nvt/@oid" /></id>
			<severity>
				<xsl:choose>
					<xsl:when test="threat='Low'">Low</xsl:when>
					<xsl:when test="threat='Medium'">Medium</xsl:when>
					<xsl:when test="threat='High'">High</xsl:when>
				</xsl:choose>
			</severity>
			<finding_txt><xsl:value-of select="description" /></finding_txt>
			<references>
				<cve />
				<bid />
				<osvdb />
				<url />
				<msf />
			</references>
		</finding>
	</xsl:for-each>
</xsl:template>

<xsl:template match="report">
<ivil version="0.2">
	<addressee>
		<program>Seccubus</program>
		<programSpecificData>
			<xsl:apply-templates select="@id" />
		</programSpecificData>
	</addressee>
	<sender>
		<scanner_type>GVM</scanner_type>
		<version><xsl:apply-templates select="results" mode="version" /></version>
		<timestamp><xsl:apply-templates select="scan_end" /></timestamp>
	</sender>
	<findings>
		<xsl:apply-templates select="results" mode="findings" />
	</findings>
</ivil>
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

<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet
    version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:func = "http://exslt.org/functions"
    xmlns:gvm="http://openvas.org"
    extension-element-prefixes="func">

  <xsl:output method="text" encoding="UTF-8" />

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

<!-- Stylesheet for generating results per threat data for Gnuplot. -->

  <func:function name="gvm:report">
    <xsl:choose>
      <xsl:when test="count(/report/report) &gt; 0">
        <func:result select="/report/report"/>
      </xsl:when>
      <xsl:otherwise>
        <func:result select="/report"/>
      </xsl:otherwise>
    </xsl:choose>
  </func:function>

<xsl:template match="/">
High <xsl:value-of select="count (gvm:report()/results/result[threat='High'])"/>
Medium <xsl:value-of select="count (gvm:report()/results/result[threat='Medium'])"/>
Low <xsl:value-of select="count (gvm:report()/results/result[threat='Low'])"/>
Log <xsl:value-of select="count (gvm:report()/results/result[threat='Log'])"/>
</xsl:template>

</xsl:stylesheet>

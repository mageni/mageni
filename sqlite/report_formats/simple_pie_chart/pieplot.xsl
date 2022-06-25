<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet
    version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

  <xsl:output method="text" encoding="UTF-8" indent="no" />
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

<!-- Stylesheet for generating python code that creates a pie plot. -->

  <xsl:template name="newline">
    <xsl:text>
</xsl:text>
  </xsl:template>

<xsl:template match="report">
from pychart import *

theme.use_color = True
theme.output_format="png"
theme.reinitialize()

data = [("High (<xsl:value-of select="count (results/result[threat='High'])"/>)",
         <xsl:value-of select="count (results/result[threat='High'])"/>),
        ("Medium (<xsl:value-of select="count (results/result[threat='Medium'])"/>)",
         <xsl:value-of select="count (results/result[threat='Medium'])"/>),
        ("Low (<xsl:value-of select="count (results/result[threat='Low'])"/>)",
         <xsl:value-of select="count (results/result[threat='Low'])"/><xsl:text>)]</xsl:text>
  <xsl:call-template name="newline"/>
  <xsl:call-template name="newline"/>
  <xsl:text>ar = area.T(size=(</xsl:text>
  <xsl:choose>
    <xsl:when test="report_format/param[name='Width']">
      <xsl:value-of select="report_format/param[name='Width']/value"/>
    </xsl:when>
    <xsl:otherwise>
      <xsl:text>400</xsl:text>
    </xsl:otherwise>
  </xsl:choose>
  <xsl:text>,</xsl:text>
  <xsl:choose>
    <xsl:when test="report_format/param[name='Height']">
      <xsl:value-of select="report_format/param[name='Height']/value"/>
    </xsl:when>
    <xsl:otherwise>
      <xsl:text>400</xsl:text>
    </xsl:otherwise>
  </xsl:choose>
  <xsl:text>), legend=None,</xsl:text>
            x_grid_style = None, y_grid_style = None)

# The "High" element is pulled out of the pie with offset=10
plot = pie_plot.T(data=data, arc_offsets=[10,0,0],
                  shadow = None, label_offset = 25,
                  fill_styles = [ fill_style.red, fill_style.yellow,
                                  fill_style.blue ],
                  arrow_style = arrow.a3)

ar.add_plot(plot)
ar.draw()
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

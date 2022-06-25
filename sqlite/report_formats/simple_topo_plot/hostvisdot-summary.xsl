<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet
  version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:output
    method = "text"
    indent = "no" />

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

<!-- Stylesheet for generating results as dot file. -->

  <xsl:template name="newline">
    <xsl:text>
</xsl:text>
  </xsl:template>

<xsl:template match="report">
digraph scan {
  <xsl:choose>
    <xsl:when test="report_format/param[name = 'Node Distance']">
      <xsl:text>  nodesep = </xsl:text>
      <xsl:value-of select="report_format/param[name = 'Node Distance']/value"/>
      <xsl:text>;</xsl:text>
    </xsl:when>
    <xsl:otherwise>
      <xsl:text>  nodesep = 8;</xsl:text>
    </xsl:otherwise>
  </xsl:choose>
  <xsl:call-template name="newline"/>
  ranksep = 2;
  overlap = "true";
  fontsize = 8.0;
  concentrate = "true";
  root = "GVM";
  "GVM" [label="GVM", style=filled, color=chartreuse3];
    <xsl:for-each select="host" >
      <xsl:variable name="current_host" select="ip"/>
      <xsl:choose>
        <xsl:when test="count(../results/result[host/text() = $current_host][threat/text() = 'High']) &gt; 0">
  "<xsl:value-of select="$current_host"/>" [label="<xsl:value-of select="$current_host"/>", style=filled, shape=Mrecord, color=red, fontcolor=white];
        </xsl:when>
        <xsl:otherwise>
          <xsl:choose>
            <xsl:when test="count(../results/result[host/text() = $current_host][threat/text() = 'Medium']) &gt; 0">
  "<xsl:value-of select="$current_host"/>" [label="<xsl:value-of select="$current_host"/>", style=filled, shape=Mrecord, color=orange, fontcolor=white];
            </xsl:when>
            <xsl:otherwise>
              <xsl:choose>
                <xsl:when test="count(../results/result[host/text() = $current_host][threat/text() = 'Low']) &gt; 0">
  "<xsl:value-of select="$current_host"/>" [label="<xsl:value-of select="$current_host"/>", style=filled, shape=Mrecord, color=cornflowerblue, fontcolor=white];
                </xsl:when>
              </xsl:choose>
            </xsl:otherwise>
          </xsl:choose>
        </xsl:otherwise>
      </xsl:choose>
      <xsl:apply-templates select="../results/result[host/text() = $current_host][port/text() = 'general/HOST-T']" mode="trace">
        <xsl:with-param name="host" select="$current_host" />
      </xsl:apply-templates>
    </xsl:for-each>
}
  </xsl:template>

  <xsl:template match="result" mode="trace">
    <xsl:param name="host"/>
    <xsl:variable name="space"><xsl:text>
</xsl:text>
    </xsl:variable>
    <xsl:variable name="fullroute" select="substring-before(substring-after(description/text(), 'traceroute:'), $space)" />
    <xsl:variable name="ports" select="substring-before(substring-after(description/text(), 'ports:'), $space)" />
    <xsl:variable name="gsm" select="substring-before($fullroute, ',')" />
    <xsl:variable name="route" select="substring-after($fullroute, ',')" />
    <xsl:variable name="nexthop" select="substring-before($route, ',')" />
    <xsl:choose>
      <xsl:when test="contains($route, ',')">
        "GVM" -> "<xsl:value-of select="$nexthop"/>";
        <xsl:call-template name="trace_recurse">
          <xsl:with-param name="trace_list" select="$route"/>
        </xsl:call-template>
      </xsl:when>
      <xsl:otherwise>
        <xsl:choose>
          <xsl:when test="$route">
            "GVM" -> "<xsl:value-of select="$route"/>";
          </xsl:when>
          <xsl:otherwise>
            "GVM" -> "127.0.0.1" [style=dashed];
          </xsl:otherwise>
        </xsl:choose>
      </xsl:otherwise>
    </xsl:choose>
    <!-- Enable the following block for port visualisation -->
    <xsl:call-template name="port_recurse">
      <xsl:with-param name="port_list" select="$ports"/>
      <xsl:with-param name="port_host" select="$host"/>
    </xsl:call-template>
</xsl:template>

  <xsl:template name="trace_recurse">
    <xsl:param name="trace_list"/>
    <xsl:choose>
      <xsl:when test="contains($trace_list, ',')">
        <xsl:variable name="head" select="substring-before($trace_list, ',')" />
        <xsl:variable name="tail" select="substring-after($trace_list, ',')"/>
        <xsl:variable name="next" select="substring-before($tail, ',')"/>
        <xsl:choose>
          <xsl:when test="($next) and not ($head = $next) and not (contains ($head, '*')) and not (contains ($next, '*'))">
            "<xsl:value-of select="$head"/>" -> "<xsl:value-of select="$next"/>";
          </xsl:when>
          <xsl:when test="not ($next) and ($tail) and not ($head = $tail) and not (contains ($head, '*')) and not (contains ($tail, '*'))">
            "<xsl:value-of select="$head"/>" -> "<xsl:value-of select="$tail"/>";
          </xsl:when>
        </xsl:choose>
        <xsl:call-template name="trace_recurse">
          <xsl:with-param name="trace_list" select="$tail"/>
        </xsl:call-template>
      </xsl:when>
    </xsl:choose>
  </xsl:template>

  <xsl:template name="port_recurse">
    <xsl:param name="port_list"/>
    <xsl:param name="port_host"/>
    <xsl:choose>
      <xsl:when test="contains($port_list, ',')">
        <xsl:variable name="head" select="substring-before($port_list, ',')" />
        <xsl:variable name="tail" select="substring-after($port_list, ',')"/>
        "<xsl:value-of select="$port_host"/>:<xsl:value-of select="$head"/>" [label ="<xsl:value-of select="$head"/>", shape="Mrecord"];
        "<xsl:value-of select="$port_host"/>" -> "<xsl:value-of select="$port_host"/>:<xsl:value-of select="$head"/>" [len = 0.2, arrowhead="none"];
        <xsl:call-template name="port_recurse">
          <xsl:with-param name="port_list" select="$tail"/>
          <xsl:with-param name="port_host" select="$port_host"/>
        </xsl:call-template>
      </xsl:when>
      <xsl:when test="$port_list and not (contains($port_list, ','))">
        "<xsl:value-of select="$port_host"/>:<xsl:value-of select="$port_list"/>" [label ="<xsl:value-of select="$port_list"/>", shape="Mrecord"];
        "<xsl:value-of select="$port_host"/>" -> "<xsl:value-of select="$port_host"/>:<xsl:value-of select="$port_list"/>" [len = 0.2, arrowhead="none"];
      </xsl:when>
    </xsl:choose>
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

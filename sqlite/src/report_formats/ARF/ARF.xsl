<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet
  version="1.0"
  xmlns:func = "http://exslt.org/functions"
  xmlns:openvas="http://openvas.org"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:ai="http://scap.nist.gov/schema/asset-identification/1.1"
  xmlns:core="http://scap.nist.gov/schema/reporting-core/1.1"
  xmlns:cpe-name="http://cpe.mitre.org/naming/2.0"
  xmlns:arf="http://scap.nist.gov/specifications/arf/index.html"
  xmlns="http://scap.nist.gov/schema/asset-reporting-format/1.1"
  extension-element-prefixes="func">
  <xsl:output
    method = "xml"
    indent = "yes" />

<!--
Copyright (C) 2012-2018 Greenbone Networks GmbH

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

<!-- Stylesheet for generating NIST ARF-compatible reports. -->

<func:function name="openvas:report">
  <xsl:choose>
    <xsl:when test="count(/report/report) &gt; 0">
      <func:result select="/report/report"/>
    </xsl:when>
    <xsl:otherwise>
      <func:result select="/report"/>
    </xsl:otherwise>
  </xsl:choose>
</func:function>

<xsl:template match="report">
  <asset-report-collection>

    <core:relationships xmlns:arfvocab="http://scap.nist.gov/vocabulary/arf/relationships/1.0#">
      <xsl:for-each select="host">

        <xsl:variable name="curr_host" select="ip/text()"/>
        <xsl:variable name="host_id" select="concat('h_', $curr_host)"/>
        <xsl:variable name="report_id" select="concat('report_', $curr_host)"/>

        <core:relationship type="arfvocab:isAbout"
                           subject="{$report_id}">
          <core:ref>
            <xsl:value-of select="$host_id"/>
          </core:ref>
        </core:relationship>
        <xsl:for-each select="detail[name = 'App']/value">
          <core:relationship type="arfvocab:isAbout"
                             subject="{$report_id}">
              <core:ref>
                <xsl:value-of select="concat('a_', $host_id, '_', position())"/>
              </core:ref>
          </core:relationship>
        </xsl:for-each>
      </xsl:for-each>
    </core:relationships>

    <assets>
      <xsl:for-each select="host">
        <xsl:variable name="host_id" select="concat('h_', ip/text())"/>
        <asset id="{$host_id}">
          <ai:computing-device>
            <xsl:for-each select="detail[name = 'OS']">
              <xsl:if test="contains(value, 'cpe:/h')">
                <cpe><xsl:value-of select="value"/></cpe>
              </xsl:if>
            </xsl:for-each>
            <xsl:if test="detail[name = 'hostname']">
              <hostname>
                <xsl:value-of select="detail[name = 'hostname']/value"/>
              </hostname>
            </xsl:if>
            <ai:connections>
              <ai:connection>
                <ai:ip-address>
                  <ai:ip-v4><xsl:value-of select="ip/text()"/></ai:ip-v4>
                </ai:ip-address>
              </ai:connection>
            </ai:connections>
          </ai:computing-device>
        </asset>
        <xsl:for-each select="detail[name = 'App']/value">
          <asset id="a_{$host_id}_{position()}">
            <ai:software>
              <cpe><xsl:value-of select="."/></cpe>
            </ai:software>
          </asset>
        </xsl:for-each>
        <xsl:if test="detail[name = 'best_os_cpe']/value">
          <asset id="os_{$host_id}_{position()}">
            <ai:software>
              <cpe>
                <xsl:value-of select="detail[name = 'best_os_cpe']/value/text()"/>
              </cpe>
            </ai:software>
          </asset>
        </xsl:if>
      </xsl:for-each>
    </assets>

    <reports>
      <xsl:for-each select="host">
        <xsl:call-template name="host-report">
          <xsl:with-param name="ip" select="ip/text()"/>
        </xsl:call-template>
      </xsl:for-each>
    </reports>
  </asset-report-collection>
</xsl:template>

<xsl:template name="host-report">
  <xsl:param name="ip"/>

  <report id="{concat('report_', $ip)}">
    <content>
      <xsl:copy>
        <xsl:for-each select="openvas:report()/results/result[host/text() = $ip]">
          <xsl:copy-of select="."/>
        </xsl:for-each>
      </xsl:copy>
    </content>
  </report>
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

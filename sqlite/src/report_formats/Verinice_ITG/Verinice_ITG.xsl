<?xml version="1.0" encoding="UTF-8"?>
<!--
Copyright (C) 2011-2018 Greenbone Networks GmbH

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

<!-- Report stylesheet for IT-Grundschutz Verinice interface.

This stylesheet extracts the tables of IT-Grundschutz
scans from the given XML scan report using a XSL
transformation with the tool xsltproc.
-->

<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:str="http://exslt.org/strings" version="1.0" extension-element-prefixes="str">
  <xsl:include href="classification-helpers.xsl"/>
  <xsl:output method="xml" encoding="UTF-8"/>
  <xsl:template match="task">
    <xsl:value-of select="@id"/>
  </xsl:template>

  <!-- Remove leading Zeros from a string -->
  <xsl:template name="removeLeadingZeros">
    <xsl:param name="originalString"/>
    <xsl:choose>
      <xsl:when test="starts-with($originalString,'0')">
        <xsl:call-template name="removeLeadingZeros">
          <xsl:with-param name="originalString">
            <xsl:value-of select="substring-after($originalString,'0' )"/>
          </xsl:with-param>
        </xsl:call-template>
      </xsl:when>
      <xsl:otherwise>
        <xsl:value-of select="$originalString"/>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <!-- Convert the status coming from GSM to a status understood by verinice -->
  <xsl:template name="status_to_umsetzung">
    <xsl:param name="status"/>
    <xsl:choose>
      <xsl:when test="$status = 'NA'">
        <xsl:text>mnums_umsetzung_entbehrlich</xsl:text>
      </xsl:when>
      <xsl:when test="$status = 'OK'">
        <xsl:text>mnums_umsetzung_ja</xsl:text>
      </xsl:when>
      <xsl:when test="$status = 'FAIL'">
        <xsl:text>mnums_umsetzung_nein</xsl:text>
      </xsl:when>
      <xsl:when test="$status = 'NS'">
        <xsl:text>mnums_umsetzung_entbehrlich</xsl:text>
      </xsl:when>
      <xsl:when test="$status = 'NI'">
        <xsl:text>mnums_umsetzung_entbehrlich</xsl:text>
      </xsl:when>
      <xsl:when test="$status = 'NC'">
        <xsl:text>mnums_umsetzung_teilweise</xsl:text>
      </xsl:when>
      <xsl:otherwise>
        <!-- leave empty as "unbearbeiitet
        <xsl:text>mnums_umsetzung_</xsl:text>
        <xsl:value-of select="$status"></xsl:value-of> -->
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>
  <!-- Convert the format of a Massnahme number to vernice's format
       example: M4.001 to M 4.1 -->
  <xsl:template name="gsm_mnum_to_ver_mnum">
    <xsl:param name="gsm_mnum"/>
    <xsl:text>M </xsl:text>
    <xsl:value-of select="substring-before(substring-after($gsm_mnum,'M'), '.')"/>
    <xsl:text>.</xsl:text>
    <xsl:call-template name="removeLeadingZeros">
      <xsl:with-param name="originalString">
        <xsl:value-of select="substring-after($gsm_mnum, '.')"/>
      </xsl:with-param>
    </xsl:call-template>
  </xsl:template>

  <!-- Convert the format of a Massnahme number to vernice's massnahmen url
       example: M4.001 to m04001 -->
  <xsl:template name="gsm_mnum_to_ver_url">
    <xsl:param name="gsm_mnum"/>
    <xsl:text>m</xsl:text>
    <xsl:variable name="major_number">
      <xsl:value-of select="substring-before(substring-after($gsm_mnum,'M'), '.')"/>
    </xsl:variable>
    <xsl:choose>
      <xsl:when test="string-length($major_number) = 1">
        <xsl:text>0</xsl:text>
        <xsl:value-of select="$major_number"></xsl:value-of>
      </xsl:when>
      <xsl:otherwise>
        <xsl:value-of select="$major_number"></xsl:value-of>
      </xsl:otherwise>
    </xsl:choose>
    <xsl:value-of select="substring-after($gsm_mnum, '.')"/>
  </xsl:template>

  <xsl:template name="itgsplit">
    <xsl:param name="elem"/>
    <xsl:param name="string"/>
    <xsl:param name="task_id"/>
    <xsl:choose>
      <xsl:when test="$elem = 'ip'">
        <xsl:if test="contains($string, '|')">
          <xsl:call-template name="itgsplit">
            <xsl:with-param name="string">
              <xsl:value-of select="substring-after($string, '|')"/>
            </xsl:with-param>
            <xsl:with-param name="elem">massnahme</xsl:with-param>
          </xsl:call-template>
        </xsl:if>
      </xsl:when>
      <xsl:when test="$elem = 'massnahme'">
        <syncAttribute>
          <name>gsm_itg_result_massnahme</name>
          <value>
            <xsl:call-template name="gsm_mnum_to_ver_mnum">
              <xsl:with-param name="gsm_mnum">
                <xsl:value-of select="substring(substring-before($string, '|'), 2, string-length(substring-before($string, '|')) - 2)"/>
              </xsl:with-param>
            </xsl:call-template>
          </value>
        </syncAttribute>
        <syncAttribute>
          <name>gsm_itg_result_url</name>
          <value>
            <xsl:call-template name="gsm_mnum_to_ver_url">
              <xsl:with-param name="gsm_mnum">
                <xsl:value-of select="substring(substring-before($string, '|'), 2, string-length(substring-before($string, '|')) - 2)"/>
              </xsl:with-param>
            </xsl:call-template>
          </value>
        </syncAttribute>
        <xsl:call-template name="itgsplit">
          <xsl:with-param name="string">
            <xsl:value-of select="substring-after($string, '|')"/>
          </xsl:with-param>
          <xsl:with-param name="elem">status</xsl:with-param>
        </xsl:call-template>
      </xsl:when>
      <xsl:when test="$elem = 'status'">
        <syncAttribute>
          <name>gsm_itg_result_status</name>
          <value><xsl:call-template name="status_to_umsetzung">
              <xsl:with-param name="status">
                <xsl:value-of select="substring(substring-before($string, '|'), 2, string-length(substring-before($string, '|')) - 2)"/>
              </xsl:with-param>
            </xsl:call-template></value>
        </syncAttribute>
        <xsl:call-template name="itgsplit">
          <xsl:with-param name="string">
            <xsl:value-of select="substring-after($string, '|')"/>
          </xsl:with-param>
          <xsl:with-param name="elem">kommentar</xsl:with-param>
        </xsl:call-template>
      </xsl:when>
      <xsl:when test="$elem = 'kommentar'">
        <syncAttribute>
          <name>gsm_itg_result_kommentar</name>
          <value>
              <xsl:text>GSM: </xsl:text><xsl:value-of select="substring($string, 2, string-length($string) - 2)"/>
          </value>
        </syncAttribute>
      </xsl:when>
    </xsl:choose>
  </xsl:template>
  <xsl:template name="get_result_uuid">
    <xsl:param name="string"/>
    <xsl:param name="task_id"/>
    <xsl:value-of select="$task_id"/>
    <xsl:text>-</xsl:text>
    <xsl:value-of select="substring(substring-before($string, '|'), 2, string-length(substring-before($string, '|')) - 2)"/>
    <xsl:text>-</xsl:text>
    <xsl:value-of select="substring(substring-before(substring-after($string, '|'), '|'), 2, string-length(substring-before(substring-after($string, '|'), '|')) - 2)"/>
  </xsl:template>
  <xsl:template match="description">
    <xsl:param name="task_id"/>
    <xsl:variable name="string" select="text()"/>
    <xsl:for-each select="str:split($string, '&quot;&#10;')">
      <xsl:variable name="line">
        <xsl:value-of select="."/>
      </xsl:variable>
      <xsl:if test="contains($line, '|')">
        <children>
          <xsl:call-template name="itgsplit">
            <xsl:with-param name="elem">ip</xsl:with-param>
            <xsl:with-param name="string">
              <xsl:value-of select="$line"/>
            </xsl:with-param>
          </xsl:call-template>
          <syncAttribute>
            <name>gsm_itg_siegel</name>
            <value>-</value>
          </syncAttribute>
          <extId>
            <xsl:call-template name="get_result_uuid">
              <xsl:with-param name="string">
                <xsl:value-of select="$line"/>
              </xsl:with-param>
              <xsl:with-param name="task_id">
                <xsl:value-of select="$task_id"/>
              </xsl:with-param>
            </xsl:call-template>
          </extId>
          <extObjectType>gsm_itg_result</extObjectType>
        </children>
      </xsl:if>
    </xsl:for-each>
  </xsl:template>
  <xsl:template match="report/host">
    <xsl:param name="task_id"/>
    <xsl:variable name="addr">
      <xsl:value-of select="host"/>
    </xsl:variable>
    <xsl:variable name="system_tags">
      <xsl:call-template name="remove-duplicates">
        <xsl:with-param name="string">
          <xsl:for-each select="/report/host[ip=$addr]/detail">
            <xsl:call-template name="generate-tags">
              <xsl:with-param name="include_apps" select="'1'"/>
            </xsl:call-template>
          </xsl:for-each>
        </xsl:with-param>
        <xsl:with-param name="newstring" select="''"/>
      </xsl:call-template>
    </xsl:variable>
    <children>
      <syncAttribute>
        <name>gsm_itg_system_ip</name>
        <value>
          <xsl:value-of select="$addr"/>
        </value>
      </syncAttribute>
      <syncAttribute>
        <name>gsm_itg_system_tags</name>
        <value><xsl:value-of select="normalize-space($system_tags)"/></value>
      </syncAttribute>
      <extId><xsl:value-of select="$task_id"/>-<xsl:value-of select="$addr"/></extId>
      <extObjectType>gsm_itg_system</extObjectType>
      <children>
        <syncAttribute>
          <name>gsm_itg_result_group_name</name>
          <value>GSM Result</value>
        </syncAttribute>
        <extId><xsl:value-of select="$task_id"/>-<xsl:value-of select="$addr"/>-results</extId>
        <extObjectType>gsm_itg_result_group</extObjectType>
        <xsl:for-each select="/report/results/result[port='general/IT-Grundschutz-T'][host/text()=$addr]">
          <xsl:apply-templates select="description">
            <xsl:with-param name="task_id">
              <xsl:value-of select="$task_id"/>
            </xsl:with-param>
          </xsl:apply-templates>
        </xsl:for-each>
      </children>
    </children>
  </xsl:template>
  <xsl:template match="/">
    <xsl:variable name="task_id">
      <xsl:call-template name="extract_organization"/>
      <!--<xsl:apply-templates select="report/task"/>-->
    </xsl:variable>
    <xsl:variable name="scan_name">
      <xsl:call-template name="extract_organization"/>
    </xsl:variable>
    <ns3:syncRequest xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
        xmlns="http://www.sernet.de/sync/data"
        xmlns:ns2="http://www.sernet.de/sync/mapping"
        xmlns:ns3="http://www.sernet.de/sync/sync"
        xsi:schemaLocation="http://www.sernet.de/sync/sync sync.xsd         http://www.sernet.de/sync/data data.xsd         http://www.sernet.de/sync/mapping mapping.xsd"
        sourceId="{$scan_name}">
      <syncData>
        <syncObject>
          <syncAttribute>
            <name>itverbund_name</name>
            <value>IT-Verbund</value>
          </syncAttribute>
          <extId><xsl:value-of select="$scan_name"/></extId>
          <extObjectType>itverbund</extObjectType>
          <children>
            <extId><xsl:value-of select="$task_id"/>-server-group</extId>
            <extObjectType>gsm_itg_server_group</extObjectType>
            <xsl:apply-templates select="report/host">
              <xsl:with-param name="task_id">
                <xsl:value-of select="$task_id"/>
              </xsl:with-param>
            </xsl:apply-templates>
          </children>
        </syncObject>
      </syncData>
      <ns2:syncMapping>
        <ns2:mapObjectType intId="itverbund" extId="itverbund">
          <ns2:mapAttributeType intId="itverbund_name" extId="itverbund_name"/>
        </ns2:mapObjectType>
        <ns2:mapObjectType intId="bstumsetzung" extId="gsm_itg_result_group">
          <ns2:mapAttributeType intId="bstumsetzung_name" extId="gsm_itg_result_group_name"/>
        </ns2:mapObjectType>
        <ns2:mapObjectType intId="mnums" extId="gsm_itg_result">
          <ns2:mapAttributeType intId="mnums_id" extId="gsm_itg_result_massnahme"/>
          <ns2:mapAttributeType intId="mnums_umsetzung" extId="gsm_itg_result_status"/>
          <ns2:mapAttributeType intId="mnums_erlaeuterung" extId="gsm_itg_result_kommentar"/>
          <ns2:mapAttributeType intId="mnums_url" extId="gsm_itg_result_url"/>
          <ns2:mapAttributeType intId="mnums_siegel" extId="gsm_itg_siegel"/>
        </ns2:mapObjectType>
        <ns2:mapObjectType intId="serverkategorie" extId="gsm_itg_server_group"/>
        <ns2:mapObjectType intId="server" extId="gsm_itg_system">
          <ns2:mapAttributeType intId="server_netadr" extId="gsm_itg_system_ip"/>
          <ns2:mapAttributeType intId="server_tag" extId="gsm_itg_system_tags"/>
        </ns2:mapObjectType>
      </ns2:syncMapping>
    </ns3:syncRequest>
  </xsl:template>
</xsl:stylesheet>

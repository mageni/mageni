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

Parameters:
- htmlfilename: should contain the filename of a html report
- filedate: should contain the reports modification time as seconds since Epoch
-->

<xsl:stylesheet
    version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:str="http://exslt.org/strings"
    xmlns:func="http://exslt.org/functions"
    xmlns:openvas="http://openvas.org"
    extension-element-prefixes="str func openvas">
  <xsl:param name="filenames_str"/>
  <xsl:param name="mimetypes_str"/>
  <xsl:param name="filedate"/>
  <xsl:include href="classification.xsl"/>
  <xsl:output method="xml" encoding="UTF-8"/>

  <func:function name="openvas:get-nvt-tag">
    <xsl:param name="tags"/>
    <xsl:param name="name"/>
    <xsl:variable name="after">
      <xsl:value-of select="substring-after (nvt/tags, concat ($name, '='))"/>
    </xsl:variable>
    <xsl:choose>
        <xsl:when test="contains ($after, '|')">
          <func:result select="substring-before ($after, '|')"/>
        </xsl:when>
        <xsl:otherwise>
          <func:result select="$after"/>
        </xsl:otherwise>
    </xsl:choose>
  </func:function>

  <func:function name="openvas:newstyle-nvt">
    <xsl:param name="nvt"/>
    <xsl:choose>
      <xsl:when test="string-length (openvas:get-nvt-tag ($nvt/tags, 'summary'))
                      and string-length (openvas:get-nvt-tag ($nvt/tags, 'affected'))
                      and string-length (openvas:get-nvt-tag ($nvt/tags, 'insight'))
                      and string-length (openvas:get-nvt-tag ($nvt/tags, 'vuldetect'))
                      and string-length (openvas:get-nvt-tag ($nvt/tags, 'impact'))
                      and string-length (openvas:get-nvt-tag ($nvt/tags, 'solution'))">
        <func:result select="1"/>
      </xsl:when>
      <xsl:otherwise>
        <func:result select="0"/>
      </xsl:otherwise>
    </xsl:choose>
  </func:function>

  <xsl:template name="newline">
    <xsl:text>
</xsl:text>
  </xsl:template>

  <xsl:template name="lowercase-string">
    <xsl:param name="string"/>
    <xsl:variable name="uppercase" select="'ABCDEFGHIJKLMNOPQRSTUVWXYZ'"/>
    <xsl:variable name="lowercase" select="'abcdefghijklmnopqrstuvwxyz'"/>

    <xsl:value-of select="translate($string, $uppercase, $lowercase)"/>
  </xsl:template>

  <xsl:template match="task">
    <xsl:value-of select="@id"/>
  </xsl:template>

  <xsl:key name="scenarios" match="/report/results/result/nvt/@oid" use="." />
  <xsl:key name="vulnerabilities" match="/report/results/result/nvt/@oid" use="." />
  <xsl:key name="controls" match="/report/results/result/notes/note/@id" use="." />

  <xsl:template name="extract_organization">
      <xsl:choose>
          <xsl:when test="string-length(report/task/user_tags/tag[name='Verinice Source ID']/value) &gt; 0">
            <xsl:value-of select="report/task/user_tags/tag[name='Verinice Source ID']/value/text()"/>
          </xsl:when>
          <xsl:otherwise>
              <xsl:value-of select="report/task/name"/>
          </xsl:otherwise>
      </xsl:choose>
  </xsl:template>

  <!-- Generate the contents of the asset description field -->
  <xsl:template name="get-details">
      <xsl:variable name="addr">
          <xsl:value-of select="ip/text()"/>
      </xsl:variable>
      <!-- Operating System as Text -->
      <syncAttribute>
          <name>gsm_os</name>
          <value>
              <xsl:choose>
                  <xsl:when test="string-length(/report/host[ip=$addr]/detail[name='best_os_txt']/value) &gt; 0">
                      <xsl:value-of select="/report/host[ip=$addr]/detail[name='best_os_txt']/value/text()"/>
                  </xsl:when>
                  <xsl:otherwise>
                      <xsl:text>Not Available</xsl:text>
                  </xsl:otherwise>
              </xsl:choose>
          </value>
      </syncAttribute>

      <!-- Operating System as CPE -->

      <syncAttribute>
          <name>gsm_os_cpe</name>
          <value>
              <xsl:choose>
                  <xsl:when test="string-length(/report/host[ip=$addr]/detail[name='best_os_cpe']/value) &gt; 0">
                      <xsl:value-of select="/report/host[ip=$addr]/detail[name='best_os_cpe']/value/text()"/>
                  </xsl:when>
                  <xsl:otherwise>
                      <xsl:text>Not Available</xsl:text>
                  </xsl:otherwise>
              </xsl:choose>
          </value>
      </syncAttribute>
      <!-- Hostname if available otherwise empty -->
      <syncAttribute>
          <name>gsm_hostname</name>
          <value>
            <xsl:call-template name="lowercase-string"><xsl:with-param name="string" select="/report/host[ip=$addr]/detail[name='hostname']/value/text()"/></xsl:call-template>
          </value>
      </syncAttribute>
      <!-- Scan started -->
      <syncAttribute>
          <name>gsm_scan_started</name>
          <value>
              <xsl:value-of select="start/text()"/>
          </value>
      </syncAttribute>
      <!-- Scan ended -->
      <syncAttribute>
          <name>gsm_scan_ended</name>
          <value>
              <xsl:value-of select="end/text()"/>
          </value>
      </syncAttribute>
      <!-- Open Ports -->
      <syncAttribute>
          <name>gsm_open_ports</name>
          <value>
              <xsl:choose>
                  <xsl:when test="string-length(/report/host[ip=$addr]/detail[name='ports']/value) &gt; 0">
                      <xsl:value-of select="/report/host[ip=$addr]/detail[name='ports']/value/text()"/>
                  </xsl:when>
                  <xsl:otherwise>
                      <xsl:text>Not Available</xsl:text>
                  </xsl:otherwise>
              </xsl:choose>
          </value>
      </syncAttribute>
      <!-- cpuinfo -->
      <syncAttribute>
          <name>gsm_cpuinfo</name>
          <value>
              <xsl:choose>
                  <xsl:when test="string-length(/report/host[ip=$addr]/detail[name='cpuinfo']/value) &gt; 0">
                      <xsl:value-of select="/report/host[ip=$addr]/detail[name='cpuinfo']/value/text()"/>
                  </xsl:when>
                  <xsl:otherwise>
                      <xsl:text>Not Available</xsl:text>
                  </xsl:otherwise>
              </xsl:choose>
          </value>
      </syncAttribute>
      <!-- memory -->
      <syncAttribute>
          <name>gsm_memory</name>
          <value>
              <xsl:choose>
                  <xsl:when test="string-length(/report/host[ip=$addr]/detail[name='meminfo']/value) &gt; 0">
                      <xsl:value-of select="/report/host[ip=$addr]/detail[name='meminfo']/value/text()"/>
                  </xsl:when>
                  <xsl:otherwise>
                      <xsl:text>Not Available</xsl:text>
                  </xsl:otherwise>
              </xsl:choose>
          </value>
      </syncAttribute>
      <!--TODO mac-address -->
      <syncAttribute>
          <name>gsm_mac_address</name>
          <value>
              <xsl:choose>
                  <xsl:when test="string-length(/report/host[ip=$addr]/detail[name='MAC']/value) &gt; 0">
                      <xsl:value-of select="/report/host[ip=$addr]/detail[name='MAC']/value/text()"/>
                  </xsl:when>
                  <xsl:otherwise>
                      <xsl:text>Not Available</xsl:text>
                  </xsl:otherwise>
              </xsl:choose>
          </value>
      </syncAttribute>
      <!-- Traceroute information -->
      <syncAttribute>
          <name>gsm_traceroute</name>
          <value>
              <xsl:choose>
                  <xsl:when test="string-length(/report/host[ip=$addr]/detail[name='traceroute']/value) &gt; 0">
                      <xsl:value-of select="/report/host[ip=$addr]/detail[name='traceroute']/value/text()"/>
                  </xsl:when>
                  <xsl:otherwise>
                      <xsl:text>Not Available</xsl:text>
                  </xsl:otherwise>
              </xsl:choose>
          </value>
      </syncAttribute>
      <!-- Installed software -->
      <syncAttribute>
          <name>gsm_installed_apps</name>
          <value>
              <xsl:choose>
                  <xsl:when test="count(/report/host[ip=$addr]/detail[name='App']) &gt; 0">
                      <xsl:for-each select="/report/host[ip=$addr]/detail[name='App']">
                          <xsl:value-of select="value/text()"/>
<xsl:text>
</xsl:text>
                      </xsl:for-each>
                  </xsl:when>
                  <xsl:otherwise>
                      <xsl:text>Not Available</xsl:text>
                  </xsl:otherwise>
              </xsl:choose>
          </value>
      </syncAttribute>
      <!-- Plain and simple ip address -->
      <syncAttribute>
          <name>gsm_ip_address</name>
          <value>
              <xsl:value-of select="$addr"/>
          </value>
      </syncAttribute>
  </xsl:template>

  <!--
       Info elements. Those are used in verinice to add an escalation
       method for automatically imported reports. Contents are static.
  -->
  <xsl:template name="info-asset">
    <xsl:param name="task_id"/>
    <children>
      <syncAttribute>
        <name>gsm_traceroute</name>
        <value></value>
      </syncAttribute>
      <syncAttribute>
        <name>gsm_cpuinfo</name>
        <value></value>
      </syncAttribute>
      <syncAttribute>
        <name>gsm_open_ports</name>
        <value></value>
      </syncAttribute>
      <syncAttribute>
        <name>asset_description</name>
        <value></value>
      </syncAttribute>
      <syncAttribute>
        <name>asset_value_availability</name>
        <value>0</value>
      </syncAttribute>
      <syncAttribute>
        <name>gsm_asset_description</name>
        <value></value>
      </syncAttribute>
      <syncAttribute>
        <name>gsm_scan_ended</name>
        <value></value>
      </syncAttribute>
      <syncAttribute>
        <name>asset_type</name>
        <value></value>
      </syncAttribute>
      <syncAttribute>
        <name>gsm_memory</name>
        <value></value>
      </syncAttribute>
      <syncAttribute>
        <name>gsm_ip_address</name>
        <value></value>
      </syncAttribute>
      <syncAttribute>
        <name>gsm_mac_address</name>
        <value></value>
      </syncAttribute>
      <syncAttribute>
        <name>gsm_scan_started</name>
        <value></value>
      </syncAttribute>
      <syncAttribute>
        <name>asset_name</name>
        <value>IS Coordinator Info</value>
      </syncAttribute>
      <syncAttribute>
        <name>gsm_hostname</name>
        <value></value>
      </syncAttribute>
      <syncAttribute>
        <name>asset_abbr</name>
        <value></value>
      </syncAttribute>
      <syncAttribute>
        <name>gsm_asset_tag</name>
        <value>gsm_system_info</value>
      </syncAttribute>
      <syncAttribute>
        <name>gsm_os_cpe</name>
        <value></value>
      </syncAttribute>
      <syncAttribute>
        <name>gsm_installed_apps</name>
        <value></value>
      </syncAttribute>
      <syncAttribute>
        <name>gsm_os</name>
        <value></value>
      </syncAttribute>
      <extId><xsl:value-of select="$task_id"/>-InfoAsset</extId>
      <extObjectType>gsm_ism_asset</extObjectType>
    </children>
  </xsl:template>
  <xsl:template name="info-vulnerability">
    <xsl:param name="task_id"/>
    <children>
      <syncAttribute>
        <name>gsm_ism_vulnerability_name</name>
        <value>IS Coordinator Info</value>
      </syncAttribute>
      <syncAttribute>
        <name>gsm_ism_vulnerability_level</name>
        <value></value>
      </syncAttribute>
      <syncAttribute>
        <name>gsm_ism_vulnerability_cvss</name>
        <value></value>
      </syncAttribute>
      <syncAttribute>
        <name>gsm_ism_vulnerability_cve</name>
        <value></value>
      </syncAttribute>
      <syncAttribute>
        <name>gsm_ism_vulnerability_description</name>
        <value></value>
      </syncAttribute>
      <extId><xsl:value-of select="$task_id"/>-InfoVulnerability</extId>
      <extObjectType>gsm_ism_vulnerability</extObjectType>
    </children>
  </xsl:template>
  <xsl:template name="info-control">
    <xsl:param name="task_id"/>
    <children>
      <syncAttribute>
        <name>control_implemented</name>
        <value>control_implemented_no</value>
      </syncAttribute>
      <syncAttribute>
        <name>gsm_ism_control_description</name>
        <xsl:choose>
          <xsl:when test="string-length(report/report_format/param[name='ISM Control Description']/value) &gt; 0">
            <value><xsl:value-of select="report/report_format/param[name='ISM Control Description']/value/text()"/></value>
          </xsl:when>
          <xsl:otherwise>
            <value>Dear IS Coordinator,

A new scan has been carried out and the results are now available in Verinice.
If responsible persons are linked to the asset groups, the tasks are already created.

Please check the results in a timely manner.

Best regards
CIS</value>
          </xsl:otherwise>
        </xsl:choose>
      </syncAttribute>
      <syncAttribute>
        <name>gsm_ism_control_tag</name>
        <value>gsm_system_info</value>
      </syncAttribute>
      <syncAttribute>
        <name>gsm_ism_control_cpe</name>
        <value></value>
      </syncAttribute>
      <syncAttribute>
        <name>control_name</name>
        <value>IS Coordinator Info</value>
      </syncAttribute>
      <extId><xsl:value-of select="$task_id"/>-InfoControl</extId>
      <extObjectType>gsm_ism_control</extObjectType>
    </children>
  </xsl:template>

  <xsl:template name="info-scenario">
    <xsl:param name="task_id"/>
      <children>
          <syncAttribute>
              <name>gsm_ism_scenario_cve</name>
              <value></value>
          </syncAttribute>
          <syncAttribute>
              <name>incident_scenario_name</name>
              <value>IS Coordinator Info</value>
          </syncAttribute>
          <syncAttribute>
              <name>gsm_ism_scenario_cvss</name>
              <value></value>
          </syncAttribute>
          <syncAttribute>
              <name>gsm_ism_scenario_level</name>
              <value></value>
          </syncAttribute>
          <syncAttribute>
              <name>gsm_ism_scenario_description</name>
              <value></value>
          </syncAttribute>
          <extId><xsl:value-of select="$task_id"/>-InfoScenario</extId>
          <extObjectType>gsm_ism_scenario</extObjectType>
      </children>
  </xsl:template>
  <xsl:template name="info-links">
    <xsl:param name="task_id"/>
        <syncLink>
            <dependant><xsl:value-of select="$task_id"/>-InfoScenario</dependant>
            <dependency><xsl:value-of select="$task_id"/>-InfoAsset</dependency>
            <relationId>rel_incscen_asset</relationId>
        </syncLink>
        <syncLink>
            <dependant><xsl:value-of select="$task_id"/>-InfoScenario</dependant>
            <dependency><xsl:value-of select="$task_id"/>-InfoVulnerability</dependency>
            <relationId>rel_incscen_vulnerability</relationId>
        </syncLink>
        <syncLink>
            <dependant><xsl:value-of select="$task_id"/>-InfoControl</dependant>
            <dependency><xsl:value-of select="$task_id"/>-InfoScenario</dependency>
            <relationId>rel_control_incscen</relationId>
        </syncLink>
  </xsl:template>
  <!-- End Info elements -->


  <xsl:template match="report/host">
    <xsl:param name="task_id"/>
    <xsl:variable name="addr">
      <xsl:value-of select="host"/>
    </xsl:variable>
    <xsl:variable name="extid">
      <xsl:choose>
        <xsl:when test="/report/host[ip=$addr]/detail[name='MAC']/value/text()">
          <xsl:value-of select="/report/host[ip=$addr]/detail[name='MAC']/value/text()"/>
        </xsl:when>
        <xsl:otherwise>
          <xsl:choose>
            <xsl:when test="/report/host[ip=$addr]/detail[name='hostname']/value/text()">
              <xsl:value-of select="/report/host[ip=$addr]/detail[name='hostname']/value/text()"/>
            </xsl:when>
            <xsl:otherwise>
              <xsl:value-of select="$addr"/>
            </xsl:otherwise>
          </xsl:choose>
        </xsl:otherwise>
      </xsl:choose>
    </xsl:variable>
    <children>
      <syncAttribute>
        <name>gsm_ism_asset_abbr</name>
        <value>
            <!-- Empty for now
          <xsl:value-of select="$addr"/> -->
        </value>
      </syncAttribute>
      <syncAttribute>
        <name>gsm_ism_asset_hostname</name>
        <value><!-- Warning can be empty -->
          <xsl:choose>
              <xsl:when test="/report/host[ip=$addr]/detail[name='hostname']/value/text()">
                <xsl:call-template name="lowercase-string"><xsl:with-param name="string" select="/report/host[ip=$addr]/detail[name='hostname']/value/text()"/></xsl:call-template>
              </xsl:when>
              <xsl:otherwise>
                  <xsl:value-of select="$addr"/>
              </xsl:otherwise>
            </xsl:choose>
        </value>
      </syncAttribute>
      <syncAttribute>
          <name>gsm_ism_asset_tags</name>
          <value>
              <xsl:for-each select="/report/host[ip=$addr]/detail[name='best_os_cpe']">
                  <xsl:call-template name="generate-tags"/>
              </xsl:for-each>
          </value>
      </syncAttribute>
      <syncAttribute>
          <!-- Everything we can scan is physical -->
          <name>gsm_ism_asset_type</name>
          <value>asset_type_phys</value>
      </syncAttribute>
      <xsl:for-each select="/report/host[ip=$addr]">
        <xsl:call-template name="get-details"/>
      </xsl:for-each>
      <syncAttribute>
        <name>gsm_ism_asset_description</name>
        <value></value>
      </syncAttribute>
      <extId><xsl:call-template name="lowercase-string"><xsl:with-param name="string" select="$extid"/></xsl:call-template></extId>
      <extObjectType>gsm_ism_asset</extObjectType>
    </children>
  </xsl:template>

  <xsl:template name="vulnerability_details">
    <xsl:param name="task_id"/>
    <children>
      <syncAttribute>
        <name>gsm_ism_vulnerability_name</name>
        <value>
          <xsl:value-of select="nvt/name"/>
        </value>
      </syncAttribute>
      <syncAttribute>
        <name>gsm_ism_vulnerability_description</name>
        <value>
          <xsl:variable name="report" select="/report"/>

          <!-- Summary -->
          <xsl:if test="openvas:newstyle-nvt (nvt)">
            <xsl:text>Summary:</xsl:text>
            <xsl:call-template name="newline"/>
            <xsl:value-of select="openvas:get-nvt-tag (nvt/tags, 'summary')"/>
            <xsl:call-template name="newline"/>
            <xsl:call-template name="newline"/>
          </xsl:if>

          <!-- Result -->
          <xsl:choose>
            <xsl:when test="openvas:newstyle-nvt (nvt)">
              <xsl:choose>
                <xsl:when test="delta/text() = 'changed'">
                  <xsl:text>Result 1:</xsl:text>
                  <xsl:call-template name="newline"/>
                  <xsl:call-template name="newline"/>
                </xsl:when>
              </xsl:choose>
              <xsl:text>Vulnerability Detection Result:</xsl:text>
              <xsl:call-template name="newline"/>
              <xsl:choose>
                <xsl:when test="string-length(description) &lt; 2">
                  <xsl:text>Vulnerability was detected according to the Vulnerability Detection Method.</xsl:text>
                </xsl:when>
                <xsl:otherwise>
                  <xsl:value-of select="description"/>
                </xsl:otherwise>
              </xsl:choose>
              <xsl:call-template name="newline"/>
            </xsl:when>
            <xsl:otherwise>
              <xsl:choose>
                <xsl:when test="delta/text() = 'changed'">
                  <xsl:text>Result 1:</xsl:text>
                  <xsl:call-template name="newline"/>
                </xsl:when>
              </xsl:choose>
              <xsl:value-of select="description"/>
              <xsl:call-template name="newline"/>
            </xsl:otherwise>
          </xsl:choose>
          <xsl:call-template name="newline"/>

          <xsl:if test="openvas:newstyle-nvt (nvt)">
            <xsl:if test="openvas:get-nvt-tag (nvt/tags, 'impact') != 'N/A'">
              <xsl:text>Impact:</xsl:text>
              <xsl:call-template name="newline"/>
              <xsl:value-of select="openvas:get-nvt-tag (nvt/tags, 'impact')"/>
              <xsl:call-template name="newline"/>
              <xsl:call-template name="newline"/>
            </xsl:if>

            <xsl:if test="openvas:get-nvt-tag (nvt/tags, 'affected') != 'N/A'">
              <xsl:text>Affected Software/OS:</xsl:text>
              <xsl:call-template name="newline"/>
              <xsl:value-of name="string" select="openvas:get-nvt-tag (nvt/tags, 'affected')"/>
              <xsl:call-template name="newline"/>
              <xsl:call-template name="newline"/>
            </xsl:if>

            <xsl:if test="(openvas:get-nvt-tag (nvt/tags, 'solution') != 'N/A') or (openvas:get-nvt-tag (nvt/tags, 'solution_type') != '')">
              <xsl:text>Solution:</xsl:text>
              <xsl:call-template name="newline"/>
              <xsl:if test="string-length (openvas:get-nvt-tag (nvt/tags, 'solution_type')) &gt; 0">
                <xsl:text>Solution type: </xsl:text>
                <xsl:value-of select="openvas:get-nvt-tag (nvt/tags, 'solution_type')"/>
                <xsl:call-template name="newline"/>
              </xsl:if>
              <xsl:value-of name="string" select="openvas:get-nvt-tag (nvt/tags, 'solution')"/>
              <xsl:call-template name="newline"/>
              <xsl:call-template name="newline"/>
            </xsl:if>

            <xsl:if test="openvas:get-nvt-tag (nvt/tags, 'insight') != 'N/A'">
              <xsl:text>Vulnerability Insight:</xsl:text>
              <xsl:call-template name="newline"/>
              <xsl:value-of select="openvas:get-nvt-tag (nvt/tags, 'insight')"/>
              <xsl:call-template name="newline"/>
              <xsl:call-template name="newline"/>
            </xsl:if>
          </xsl:if>

          <xsl:choose>
            <xsl:when test="(nvt/cvss_base &gt; 0) or (cve/cvss_base &gt; 0)">
              <xsl:text>Vulnerability Detection Method:</xsl:text>
            </xsl:when>
            <xsl:otherwise>
              <xsl:text>Log Method:</xsl:text>
            </xsl:otherwise>
          </xsl:choose>
          <xsl:call-template name="newline"/>
          <xsl:value-of select="openvas:get-nvt-tag (nvt/tags, 'vuldetect')"/>
          <xsl:call-template name="newline"/>
          <xsl:text>Details:</xsl:text>
          <xsl:call-template name="newline"/>
          <xsl:choose>
            <xsl:when test="nvt/@oid = 0">
              <xsl:if test="delta/text()">
                <xsl:call-template name="newline"/>
              </xsl:if>
            </xsl:when>
            <xsl:otherwise>
              <xsl:variable name="max" select="77"/>
              <xsl:choose>
                <xsl:when test="string-length(nvt/name) &gt; $max">
                  <xsl:value-of select="substring(nvt/name, 0, $max)"/>...
                </xsl:when>
                <xsl:otherwise>
                  <xsl:value-of select="nvt/name"/>
                </xsl:otherwise>
              </xsl:choose>
              <xsl:call-template name="newline"/>
              <xsl:text>(OID: </xsl:text>
              <xsl:value-of select="nvt/@oid"/>
              <xsl:text>)</xsl:text>
              <xsl:call-template name="newline"/>
            </xsl:otherwise>
          </xsl:choose>

          <xsl:if test="scan_nvt_version != ''">
            <xsl:text>Version used: </xsl:text>
            <xsl:value-of select="scan_nvt_version"/>
            <xsl:call-template name="newline"/>
          </xsl:if>

          <xsl:if test="count (detection)">
            <xsl:text>Product Detection Result:</xsl:text>
            <xsl:call-template name="newline"/>
            <xsl:text>Product: </xsl:text>
            <xsl:value-of select="detection/result/details/detail[name = 'product']/value/text()"/>
            <xsl:call-template name="newline"/>
            <xsl:text>Method: </xsl:text>
            <xsl:call-template name="newline"/>
            <xsl:value-of select="detection/result/details/detail[name = 'source_name']/value/text()"/>
            <xsl:call-template name="newline"/>
            <xsl:text>(OID: </xsl:text>
            <xsl:value-of select="detection/result/details/detail[name = 'source_oid']/value/text()"/>)
            <xsl:call-template name="newline"/>
          </xsl:if>
        </value>
      </syncAttribute>
      <syncAttribute>
        <name>gsm_ism_vulnerability_cve</name>
        <value>
          <xsl:value-of select="nvt/cve"/>
        </value>
      </syncAttribute>
      <syncAttribute>
        <name>gsm_ism_vulnerability_level</name>
        <value>
          <xsl:value-of select="threat"/>
        </value>
      </syncAttribute>
      <syncAttribute>
        <name>gsm_ism_vulnerability_cvss</name>
        <value>
          <xsl:value-of select="severity"/>
        </value>
      </syncAttribute>
      <extId><xsl:value-of select="$task_id"/>-<xsl:value-of select="nvt/@oid"/>-vulnerability</extId>
      <extObjectType>gsm_ism_vulnerability</extObjectType>
    </children>
  </xsl:template>

  <xsl:template name="control_details">
    <xsl:param name="task_id"/>
    <!-- Filter out lines starting with + and create a comma separated list of them-->
    <xsl:variable name="description">
      <xsl:for-each select="str:split(text, '&#10;')">
        <xsl:if test="substring(.,0,2) != '+'">
          <xsl:value-of select="."/>
          <xsl:text>&#10;</xsl:text>
        </xsl:if>
      </xsl:for-each>
    </xsl:variable>
    <xsl:variable name="tag_list">
      <xsl:for-each select="str:split(text, '&#10;')">
        <xsl:if test="substring(.,0,2) = '+'">
          <xsl:value-of select="substring(.,2)"/>
          <xsl:text>,</xsl:text>
        </xsl:if>
      </xsl:for-each>
    </xsl:variable>
    <!-- Join the filtered list to be nicely cvs formatted
         we don't want poor verince to have to parse too much-->
    <xsl:variable name="joined_list">
      <xsl:for-each select="str:split($tag_list, ',')">
        <xsl:value-of select="."/>
        <xsl:if test="position() != last()">
          <xsl:text>,</xsl:text>
        </xsl:if>
      </xsl:for-each>
    </xsl:variable>
    <children>
      <syncAttribute>
        <name>gsm_ism_control_name</name>
        <value>
          <xsl:value-of select="nvt/name"/>
        </value>
      </syncAttribute>
      <syncAttribute>
        <name>control_implemented</name>
        <value>control_implemented_no</value>
      </syncAttribute>
      <syncAttribute>
        <name>gsm_ism_control_description</name>
        <value>
          <xsl:value-of select="$description"/>
        </value>
      </syncAttribute>
      <syncAttribute>
        <name>gsm_ism_control_cpe</name>
        <value>
          <xsl:choose>
            <xsl:when test="count(../../detection)">
              <xsl:value-of select="../../detection/result/details/detail[name = 'product']/value/text()"/>
            </xsl:when>
            <xsl:otherwise>Unknown</xsl:otherwise>
          </xsl:choose>
          </value>
        </syncAttribute>
        <xsl:if test="string-length($joined_list)">
          <syncAttribute>
            <name>gsm_ism_control_tag</name>
            <value><xsl:value-of select="$joined_list"/></value>
          </syncAttribute>
        </xsl:if>
      <extId><xsl:value-of select="$task_id"/>-<xsl:value-of select="@id"/>-control</extId>
      <extObjectType>gsm_ism_control</extObjectType>
    </children>
  </xsl:template>

  <!-- Details of a scenario this is called in the context of an NVT
       element -->
  <xsl:template name="scenario_details">
    <xsl:param name="task_id"/>
    <xsl:variable name="cur_oid">
      <!-- Workaround to avoid confusion in select statements -->
      <xsl:value-of select="@oid"/>
    </xsl:variable>
    <children>
      <syncAttribute>
        <name>gsm_ism_scenario_name</name>
        <value>
          <xsl:value-of select="name"/>
        </value>
      </syncAttribute>
      <syncAttribute>
        <name>gsm_ism_scenario_cve</name>
        <value>
          <xsl:value-of select="cve"/>
        </value>
      </syncAttribute>
      <syncAttribute>
        <name>gsm_ism_scenario_level</name>
        <value>
          <xsl:value-of select="../threat"/>
        </value>
      </syncAttribute>
      <syncAttribute>
        <name>gsm_ism_scenario_description</name>
        <value>
          <xsl:value-of select="/report/results/result[nvt/@oid = $cur_oid]/description/text()"/>
        </value>
      </syncAttribute>
      <syncAttribute>
        <name>gsm_ism_scenario_cvss</name>
        <value>
          <xsl:value-of select="cvss_base"/>
        </value>
      </syncAttribute>
      <extId><xsl:value-of select="$task_id"/>-<xsl:value-of select="$cur_oid"/>-scenario</extId>
      <extObjectType>gsm_ism_scenario</extObjectType>
    </children>
  </xsl:template>

  <xsl:template name="create_links">
    <xsl:param name="task_id"/>
    <xsl:variable name="cur_oid">
      <!-- Workaround to avoid confusion in select statements -->
      <xsl:value-of select="@oid"/>
    </xsl:variable>

    <xsl:call-template name="info-links">
      <xsl:with-param name="task_id">
        <xsl:value-of select="$task_id"/>
      </xsl:with-param>
    </xsl:call-template>

    <xsl:for-each select="/report/results/result[nvt/@oid = $cur_oid]">
      <syncLink>
        <dependant><xsl:value-of select="$task_id"/>-<xsl:value-of select="$cur_oid"/>-scenario</dependant>
        <dependency><xsl:value-of select="$task_id"/>-<xsl:value-of select="$cur_oid"/>-vulnerability</dependency>
        <relationId>rel_incscen_vulnerability</relationId>
      </syncLink>
      <syncLink>
        <dependant><xsl:value-of select="$task_id"/>-<xsl:value-of select="$cur_oid"/>-scenario</dependant>
        <xsl:variable name="addr">
          <xsl:value-of select="host"/>
        </xsl:variable>
        <xsl:variable name="extid">
          <xsl:choose>
            <xsl:when test="/report/host[ip=$addr]/detail[name='MAC']/value/text()">
              <xsl:value-of select="/report/host[ip=$addr]/detail[name='MAC']/value/text()"/>
            </xsl:when>
            <xsl:otherwise>
              <xsl:choose>
                <xsl:when test="/report/host[ip=$addr]/detail[name='hostname']/value/text()">
                  <xsl:value-of select="/report/host[ip=$addr]/detail[name='hostname']/value/text()"/>
                </xsl:when>
                <xsl:otherwise>
                  <xsl:value-of select="$addr"/>
                </xsl:otherwise>
              </xsl:choose>
            </xsl:otherwise>
          </xsl:choose>
        </xsl:variable>
        <dependency><xsl:call-template name="lowercase-string"><xsl:with-param name="string" select="$extid"/></xsl:call-template></dependency>
        <relationId>rel_incscen_asset</relationId>
      </syncLink>
    </xsl:for-each>
    <xsl:for-each select="/report/results/result/notes/note[nvt/@oid = $cur_oid]">
      <syncLink>
        <dependant><xsl:value-of select="$task_id"/>-<xsl:value-of select="@id"/>-control</dependant>
        <dependency><xsl:value-of select="$task_id"/>-<xsl:value-of select="$cur_oid"/>-scenario</dependency>
        <relationId>rel_control_incscen</relationId>
      </syncLink>
    </xsl:for-each>
  </xsl:template>

  <!-- The root Match -->
  <xsl:template match="/">
    <xsl:variable name="task_id">
      <xsl:call-template name="extract_organization"/>
      <!--<xsl:apply-templates select="report/task"/>-->
    </xsl:variable>
    <xsl:variable name="scan_name">
      <xsl:call-template name="extract_organization"/>
    </xsl:variable>

    <ns3:syncRequest
      xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      xmlns="http://www.sernet.de/sync/data"
      xmlns:ns2="http://www.sernet.de/sync/mapping"
      xmlns:ns3="http://www.sernet.de/sync/sync"
      xsi:schemaLocation="http://www.sernet.de/sync/sync sync.xsd         http://www.sernet.de/sync/data data.xsd         http://www.sernet.de/sync/mapping mapping.xsd"
      sourceId="{$scan_name}">
      <syncData>
        <syncObject>
          <syncAttribute>
            <name>itverbund_name</name>
            <value><xsl:value-of select="$scan_name"/></value>
          </syncAttribute>
          <syncAttribute>
            <name>gsm_tag</name>
            <value>ap-GSM</value>
          </syncAttribute>
          <extId><xsl:value-of select="$scan_name"/></extId>
          <extObjectType>itverbund</extObjectType>
          <children>
            <syncAttribute>
              <name>gsm_ism_assets_group_name</name>
              <value>Assets GSM-Scan</value>
            </syncAttribute>
            <extId><xsl:value-of select="$task_id"/>-ism-assets</extId>
            <extObjectType>gsm_ism_assets</extObjectType>
            <xsl:apply-templates select="report/host">
              <xsl:with-param name="task_id">
                <xsl:value-of select="$task_id"/>
              </xsl:with-param>
            </xsl:apply-templates>
            <xsl:call-template name="info-asset">
              <xsl:with-param name="task_id">
                <xsl:value-of select="$task_id"/>
              </xsl:with-param>
            </xsl:call-template>
          </children>
          <children>
            <syncAttribute>
              <name>gsm_ism_vulnerabilities_group_name</name>
              <value>Vulnerabilities GSM-Scan</value>
            </syncAttribute>
            <extId><xsl:value-of select="$task_id"/>-ism-vulnerabilities</extId>
            <extObjectType>gsm_ism_vulnerabilities</extObjectType>
            <xsl:for-each select="/report/results/result[count(notes/note) &gt; 0 and threat != 'False Positive']/nvt[generate-id(@oid) = generate-id(key('vulnerabilities', @oid)[1])]/..">
              <xsl:call-template name="vulnerability_details">
                <xsl:with-param name="task_id">
                  <xsl:value-of select="$task_id"/>
                </xsl:with-param>
              </xsl:call-template>
            </xsl:for-each>
            <xsl:call-template name="info-vulnerability">
              <xsl:with-param name="task_id">
                <xsl:value-of select="$task_id"/>
              </xsl:with-param>
            </xsl:call-template>
          </children>
          <children>
            <syncAttribute>
              <name>gsm_ism_controls_group_name</name>
              <value>Controls GSM-Scan</value>
            </syncAttribute>
            <extId><xsl:value-of select="$task_id"/>-ism-controls</extId>
            <extObjectType>gsm_ism_controls</extObjectType>
            <xsl:for-each select="/report/results/result/notes/note[generate-id(@id) = generate-id(key('controls', @id)[1])]">
              <xsl:call-template name="control_details">
                <xsl:with-param name="task_id">
                  <xsl:value-of select="$task_id"/>
                </xsl:with-param>
              </xsl:call-template>
            </xsl:for-each>
            <xsl:call-template name="info-control">
              <xsl:with-param name="task_id">
                <xsl:value-of select="$task_id"/>
              </xsl:with-param>
            </xsl:call-template>
          </children>
          <children>
            <syncAttribute>
              <name>gsm_ism_scenarios_group_name</name>
              <value>Scenarios GSM-Scan</value>
            </syncAttribute>
            <extId><xsl:value-of select="$task_id"/>-ism-scenario</extId>
            <extObjectType>gsm_ism_scenarios</extObjectType>
            <!-- Only create one scenario per NVT -->
            <xsl:for-each select="/report/results/result[count(notes/note) &gt; 0 and threat != 'False Positive']/nvt[generate-id(@oid) = generate-id(key('scenarios', @oid)[1])]">
              <xsl:call-template name="scenario_details">
                <xsl:with-param name="task_id">
                  <xsl:value-of select="$task_id"/>
                </xsl:with-param>
              </xsl:call-template>
            </xsl:for-each>
            <xsl:call-template name="info-scenario">
              <xsl:with-param name="task_id">
                <xsl:value-of select="$task_id"/>
              </xsl:with-param>
            </xsl:call-template>
          </children>
        <!--        <file>
            <syncAttribute>
                <name>attachment_file_name</name>
                <value><xsl:value-of select="$filename"/></value>
            </syncAttribute>
            <syncAttribute>
                <name>attachment_name</name>
                <value><xsl:value-of select="$filename"/></value>
            </syncAttribute>
            <syncAttribute>
                <name>attachment_date</name>
                <value><xsl:value-of select="$filedate"/>000</value>
            </syncAttribute>
            <syncAttribute>
                <name>attachment_mime_type</name>
                <value>xml</value>
            </syncAttribute>
            <extId><xsl:value-of select="$filename"/></extId>
            <file>files/<xsl:value-of select="$filename"/></file>
        </file> -->
        <xsl:choose>
          <xsl:when test="report/report_format/param[name='Attached report formats'] != ''">
            <xsl:variable name="filenames" select="str:tokenize($filenames_str,'|')"/>
            <xsl:variable name="mimetypes" select="str:tokenize($mimetypes_str,'|')"/>
            <xsl:for-each select="$filenames">
              <xsl:variable name="position" select="position()"/>
        <file>
            <syncAttribute>
                <name>attachment_file_name</name>
                <value><xsl:value-of select="."/></value>
            </syncAttribute>
            <syncAttribute>
                <name>attachment_name</name>
                <value><xsl:value-of select="."/></value>
            </syncAttribute>
            <syncAttribute>
                <name>attachment_date</name>
                <value><xsl:value-of select="$filedate"/>000</value>
            </syncAttribute>
            <syncAttribute>
                <name>attachment_mime_type</name>
                <value><xsl:value-of select="$mimetypes[$position]"/></value>
            </syncAttribute>
            <extId><xsl:value-of select="."/></extId>
            <file>files/<xsl:value-of select="."/></file>
        </file>
            </xsl:for-each>
          </xsl:when>
        </xsl:choose>

        </syncObject>
        <xsl:for-each select="/report/results/result[count(notes/note) &gt; 0 and threat != 'False Positive']/nvt[generate-id(@oid) = generate-id(key('scenarios', @oid)[1])]">
          <xsl:call-template name="create_links">
            <xsl:with-param name="task_id">
              <xsl:value-of select="$task_id"/>
            </xsl:with-param>
          </xsl:call-template>
        </xsl:for-each>
    </syncData>

    <ns2:syncMapping>
      <!-- Org Name  / The root entity -->
      <ns2:mapObjectType intId="org" extId="itverbund">
        <ns2:mapAttributeType intId="org_name" extId="itverbund_name"/>
        <ns2:mapAttributeType intId="org_tag" extId="gsm_tag"/>
      </ns2:mapObjectType>

      <!-- Asset / Host -->
      <ns2:mapObjectType intId="asset" extId="gsm_ism_asset">
        <ns2:mapAttributeType intId="asset_abbr" extId="gsm_ism_asset_abbr"/>
        <ns2:mapAttributeType intId="asset_name" extId="gsm_ism_asset_hostname"/>
        <ns2:mapAttributeType intId="asset_type" extId="gsm_ism_asset_type"/>
        <ns2:mapAttributeType intId="gsm_asset_tag" extId="gsm_ism_asset_tags"/>
        <ns2:mapAttributeType intId="gsm_asset_description" extId="gsm_ism_asset_description"/>
        <ns2:mapAttributeType intId="gsm_installed_apps" extId="gsm_installed_apps"/>
        <ns2:mapAttributeType intId="gsm_traceroute" extId="gsm_traceroute"/>
        <ns2:mapAttributeType intId="gsm_memory" extId="gsm_memory"/>
        <ns2:mapAttributeType intId="gsm_cpuinfo" extId="gsm_cpuinfo"/>
        <ns2:mapAttributeType intId="gsm_os" extId="gsm_os"/>
        <ns2:mapAttributeType intId="gsm_os_cpe" extId="gsm_os_cpe"/>
        <ns2:mapAttributeType intId="gsm_open_ports" extId="gsm_open_ports"/>
        <ns2:mapAttributeType intId="gsm_scan_ended" extId="gsm_scan_ended"/>
        <ns2:mapAttributeType intId="gsm_scan_started" extId="gsm_scan_started"/>
        <ns2:mapAttributeType intId="gsm_hostname" extId="gsm_hostname"/>
        <ns2:mapAttributeType intId="gsm_mac_address" extId="gsm_mac_address"/>
        <ns2:mapAttributeType intId="gsm_ip_address" extId="gsm_ip_address"/>
      </ns2:mapObjectType>

      <!-- Vulnerability / NVT -->
      <ns2:mapObjectType intId="vulnerability" extId="gsm_ism_vulnerability">
        <ns2:mapAttributeType intId="vulnerability_name" extId="gsm_ism_vulnerability_name"/>
        <ns2:mapAttributeType intId="gsm_ism_vulnerability_description" extId="gsm_ism_vulnerability_description"/>
        <ns2:mapAttributeType intId="gsm_ism_vulnerability_cvss" extId="gsm_ism_vulnerability_cvss"/>
        <ns2:mapAttributeType intId="gsm_ism_vulnerability_cve" extId="gsm_ism_vulnerability_cve"/>
        <ns2:mapAttributeType intId="gsm_ism_vulnerability_level" extId="gsm_ism_vulnerability_level"/>
      </ns2:mapObjectType>

      <!-- Control / Note on a vulnerability -->
      <ns2:mapObjectType intId="control" extId="gsm_ism_control">
       <ns2:mapAttributeType intId="control_name" extId="gsm_ism_control_name"/>
       <ns2:mapAttributeType intId="control_implemented" extId="control_implemented"/>
       <ns2:mapAttributeType intId="gsm_ism_control_description" extId="gsm_ism_control_description"/>
       <ns2:mapAttributeType intId="gsm_ism_control_cpe" extId="gsm_ism_control_cpe"/>
       <ns2:mapAttributeType intId="gsm_ism_control_tag" extId="gsm_ism_control_tag"/>
      </ns2:mapObjectType>

      <!-- Scenario / NVT -->
      <ns2:mapObjectType intId="incident_scenario" extId="gsm_ism_scenario">
        <ns2:mapAttributeType intId="incident_scenario_name" extId="gsm_ism_scenario_name"/>
        <ns2:mapAttributeType intId="gsm_ism_scenario_description" extId="gsm_ism_scenario_description"/>
        <ns2:mapAttributeType intId="gsm_ism_scenario_cve" extId="gsm_ism_scenario_cve"/>
        <ns2:mapAttributeType intId="gsm_ism_scenario_level" extId="gsm_ism_scenario_level"/>
        <ns2:mapAttributeType intId="gsm_ism_scenario_cvss" extId="gsm_ism_scenario_cvss"/>
      </ns2:mapObjectType>

      <!-- The Rest -->
      <ns2:mapObjectType intId="assetgroup" extId="gsm_ism_assets">
        <ns2:mapAttributeType intId="assetgroup_name" extId="gsm_ism_assets_group_name"/>
      </ns2:mapObjectType>

      <ns2:mapObjectType intId="vulnerability_group" extId="gsm_ism_vulnerabilities">
        <ns2:mapAttributeType intId="vulnerability_group_name" extId="gsm_ism_vulnerabilities_group_name"/>
      </ns2:mapObjectType>

      <ns2:mapObjectType intId="controlgroup" extId="gsm_ism_controls">
        <ns2:mapAttributeType intId="controlgroup_name" extId="gsm_ism_controls_group_name"/>
      </ns2:mapObjectType>

      <ns2:mapObjectType intId="incident_scenario_group" extId="gsm_ism_scenarios">
        <ns2:mapAttributeType intId="incident_scenario_group_name" extId="gsm_ism_scenarios_group_name"/>
      </ns2:mapObjectType>

      <ns2:mapObjectType intId="attachment" extId="attachment">
          <ns2:mapAttributeType intId="attachment_text" extId="attachment_text"/>
          <ns2:mapAttributeType intId="attachment_file_name" extId="attachment_file_name"/>
          <ns2:mapAttributeType intId="attachment_version" extId="attachment_version"/>
          <ns2:mapAttributeType intId="attachment_name" extId="attachment_name"/>
          <ns2:mapAttributeType intId="attachment_date" extId="attachment_date"/>
          <ns2:mapAttributeType intId="attachment_mime_type" extId="attachment_mime_type"/>
          <ns2:mapAttributeType intId="attachment_approval" extId="attachment_approval"/>
          <ns2:mapAttributeType intId="attachment_publish" extId="attachment_publish"/>
      </ns2:mapObjectType>
    </ns2:syncMapping>
  </ns3:syncRequest>
  </xsl:template>
</xsl:stylesheet>

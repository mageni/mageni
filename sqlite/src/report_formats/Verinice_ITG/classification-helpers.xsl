<?xml version="1.0" encoding="UTF-8"?>
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

<!-- Helper templates to classify Hosts for Verinice.

This stylesheet contains helper templates used for
a classification of Hosts that is used by Verinice
-->

<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:str="http://exslt.org/strings" version="1.0" extension-element-prefixes="str">
  <!--
    Notice:
    The space in the end of each tag works as separator
-->
  <xsl:template name="generate-tags">
    <xsl:param name="include_apps"/>
    <xsl:choose>
      <!--
             Check for Operating system with best_os_cpe and OS
             list of os vendors taken from the official-cpe-dictionary_v.2.2
         -->
      <xsl:when test="name='OS' or name='best_os_cpe'">
        <xsl:choose>
          <xsl:when test="contains(value, 'cpe:/o:3com')">
            <xsl:text>
              <!-- TODO -->
            </xsl:text>
          </xsl:when>
          <xsl:when test="contains(value, 'cpe:/o:alcatel')">
            <xsl:text>
              <!-- TODO -->
            </xsl:text>
          </xsl:when>
          <xsl:when test="contains(value, 'cpe:/o:apple')">
            <xsl:choose>
              <xsl:when test="contains(value, 'cpe:/o:apple:iphone')">
                <xsl:text>gsm_system_smartphone </xsl:text>
              </xsl:when>
              <xsl:when test="contains(value, 'cpe:/o:apple:mac_os')">
                <xsl:text>gsm_system_macos gsm_system_unix </xsl:text>
              </xsl:when>
            </xsl:choose>
          </xsl:when>
          <xsl:when test="contains(value, 'cpe:/o:bluecoat')">
            <xsl:text>
              <!-- TODO -->
            </xsl:text>
          </xsl:when>
          <xsl:when test="contains(value, 'cpe:/o:brocade')">
            <xsl:text>
              <!-- TODO -->
            </xsl:text>
          </xsl:when>
          <xsl:when test="contains(value, 'cpe:/o:canonical')">
            <xsl:text>gsm_system_unix gsm_system_linux </xsl:text>
          </xsl:when>
          <xsl:when test="contains(value, 'cpe:/o:centos')">
            <xsl:text>gsm_system_unix gsm_system_linux </xsl:text>
          </xsl:when>
          <xsl:when test="contains(value, 'cpe:/o:cisco')">
            <xsl:text>
              <!-- TODO -->
            </xsl:text>
          </xsl:when>
          <xsl:when test="contains(value, 'cpe:/o:compaq')">
            <xsl:text>
              <!-- TODO -->
            </xsl:text>
          </xsl:when>
          <xsl:when test="contains(value, 'cpe:/o:conectiva')">
            <xsl:text>
              <!-- TODO -->
            </xsl:text>
          </xsl:when>
          <xsl:when test="contains(value, 'cpe:/o:corel')">
            <xsl:text>
              <!-- TODO -->
            </xsl:text>
          </xsl:when>
          <xsl:when test="contains(value, 'cpe:/o:cray')">
            <xsl:text>
              <!-- TODO -->
            </xsl:text>
          </xsl:when>
          <xsl:when test="contains(value, 'cpe:/o:debian')">
            <xsl:text>gsm_system_unix gsm_system_linux </xsl:text>
          </xsl:when>
          <xsl:when test="contains(value, 'cpe:/o:engardelinux')">
            <xsl:text>gsm_system_unix gsm_system_linux </xsl:text>
          </xsl:when>
          <xsl:when test="contains(value, 'cpe:/o:extremenetworks')">
            <xsl:text>
              <!-- TODO -->
            </xsl:text>
          </xsl:when>
          <xsl:when test="contains(value, 'cpe:/o:f5')">
            <xsl:text>gsm_system_unix gsm_system_linux </xsl:text>
          </xsl:when>
          <xsl:when test="contains(value, 'cpe:/o:fedoraproject')">
            <xsl:text>gsm_system_unix gsm_system_linux </xsl:text>
          </xsl:when>
          <xsl:when test="contains(value, 'cpe:/o:freebsd')">
            <xsl:text>gsm_system_unix </xsl:text>
          </xsl:when>
          <xsl:when test="contains(value, 'cpe:/o:freenas')">
            <xsl:text>
              <!-- TODO -->
            </xsl:text>
          </xsl:when>
          <xsl:when test="contains(value, 'cpe:/o:gentoo')">
            <xsl:text>gsm_system_unix </xsl:text>
          </xsl:when>
          <xsl:when test="contains(value, 'cpe:/o:google:android')">
            <xsl:text>gsm_system_smartphone </xsl:text>
          </xsl:when>
          <xsl:when test="contains(value, 'cpe:/o:greenbone')">
            <xsl:text>gsm_system_unix gsm_system_linux </xsl:text>
          </xsl:when>
          <xsl:when test="contains(value, 'cpe:/o:hp')">
            <xsl:text>
              <!-- TODO -->
            </xsl:text>
          </xsl:when>
          <xsl:when test="contains(value, 'cpe:/o:ibm')">
            <xsl:text>
              <!-- TODO -->
            </xsl:text>
          </xsl:when>
          <xsl:when test="contains(value, 'cpe:/o:juniper')">
            <xsl:text>
              <!-- TODO -->
            </xsl:text>
          </xsl:when>
          <xsl:when test="contains(value, 'cpe:/o:linux')">
            <xsl:text>gsm_system_unix gsm_system_linux </xsl:text>
          </xsl:when>
          <xsl:when test="contains(value, 'cpe:/o:mandrakesoft')">
            <xsl:text>gsm_system_unix gsm_system_linux </xsl:text>
          </xsl:when>
          <xsl:when test="contains(value, 'cpe:/o:mandriva')">
            <xsl:text>gsm_system_unix gsm_system_linux </xsl:text>
          </xsl:when>
          <xsl:when test="contains(value, 'cpe:/o:microsoft')">
            <xsl:choose>
              <xsl:when test="contains(value, 'cpe:/o:microsoft:ms-dos')">
                <xsl:text>gsm_system_dos </xsl:text>
              </xsl:when>
              <xsl:when test="contains(value, 'cpe:/o:microsoft:windows-9x')">
                <xsl:text>gsm_system_win9x </xsl:text>
              </xsl:when>
              <xsl:when test="contains(value, 'cpe:/o:microsoft:windows-ce')">
                <xsl:text>gsm_system_smartphone </xsl:text>
              </xsl:when>
              <xsl:when test="contains(value, 'cpe:/o:microsoft:windows_mobile')">
                <xsl:text>gsm_system_smartphone </xsl:text>
              </xsl:when>
              <xsl:when test="contains(value, 'cpe:/o:microsoft:windows_2000')">
                <xsl:text>gsm_system_win2k </xsl:text>
              </xsl:when>
              <xsl:when test="contains(value, 'cpe:/o:microsoft:windows_vista')">
                <xsl:text>gsm_system_vista </xsl:text>
              </xsl:when>
              <xsl:when test="contains(value, 'cpe:/o:microsoft:windows-nt')">
                <xsl:text>gsm_system_winnt </xsl:text>
              </xsl:when>
              <xsl:when test="contains(value, 'cpe:/o:microsoft:windows_nt')">
                <xsl:text>gsm_system_winnt </xsl:text>
              </xsl:when>
              <xsl:when test="contains(value, 'cpe:/o:microsoft:windows_server_2003')">
                <xsl:text>gsm_system_win2003 </xsl:text>
              </xsl:when>
              <xsl:when test="contains(value, 'cpe:/o:microsoft:windows_2003')">
                <xsl:text>gsm_system_win2003 </xsl:text>
              </xsl:when>
              <xsl:when test="contains(value, 'cpe:/o:microsoft:windows_7')">
                <xsl:text>gsm_system_win7 </xsl:text>
              </xsl:when>
              <xsl:when test="contains(value, 'cpe:/o:microsoft:windows_server_2008')">
                <xsl:text>gsm_system_win2008 </xsl:text>
              </xsl:when>
              <xsl:when test="contains(value, 'cpe:/o:microsoft:windows_2008')">
                <xsl:text>gsm_system_win2008 </xsl:text>
              </xsl:when>
              <xsl:when test="contains(value, 'cpe:/o:microsoft:windows_xp')">
                <xsl:text>gsm_system_winxp </xsl:text>
              </xsl:when>
              <xsl:otherwise>
                <xsl:text>
                  <!--TODO Generic windows? -->
                </xsl:text>
              </xsl:otherwise>
            </xsl:choose>
          </xsl:when>
          <xsl:when test="contains(value, 'cpe:/o:nec')">
            <xsl:text>
              <!-- TODO -->
            </xsl:text>
          </xsl:when>
          <xsl:when test="contains(value, 'cpe:/o:netbsd')">
            <xsl:text>gsm_system_unix gsm_system_bsd </xsl:text>
          </xsl:when>
          <xsl:when test="contains(value, 'cpe:/o:nokia')">
            <xsl:text>gsm_system_smartphone </xsl:text>
          </xsl:when>
          <xsl:when test="contains(value, 'cpe:/o:novell')">
            <!-- Check Netware 3 and 4 -->
            <xsl:choose>
              <xsl:when test="contains(value, 'cpe:/o:novell:netware:3')">
                <xsl:text>gsm_system_netware3 </xsl:text>
              </xsl:when>
              <xsl:when test="contains(value, 'cpe:/o:novell:netware:4')">
                <xsl:text>gsm_system_netware4 </xsl:text>
              </xsl:when>
              <!-- TODO what about the rest? -->
              <xsl:otherwise>
                <xsl:text>gsm_system_unix </xsl:text>
              </xsl:otherwise>
            </xsl:choose>
          </xsl:when>
          <xsl:when test="contains(value, 'cpe:/o:openbsd')">
            <xsl:text>gsm_system_unix </xsl:text>
          </xsl:when>
          <xsl:when test="contains(value, 'cpe:/o:redhat')">
            <xsl:text>gsm_system_unix </xsl:text>
          </xsl:when>
          <xsl:when test="contains(value, 'cpe:/o:rim:blackberry')">
            <!-- Currently 2012.03.20 only playbook os as cpe from rim -->
            <xsl:text>gsm_system_smartphone </xsl:text>
          </xsl:when>
          <xsl:when test="contains(value, 'cpe:/o:sgi')">
            <!-- irix or advanced linux -->
            <xsl:text>gsm_system_unix </xsl:text>
          </xsl:when>
          <xsl:when test="contains(value, 'cpe:/o:siemens')">
            <xsl:text>
              <!-- TODO -->
            </xsl:text>
          </xsl:when>
          <xsl:when test="contains(value, 'cpe:/o:slackware')">
            <xsl:text>gsm_system_unix gsm_system_linux </xsl:text>
          </xsl:when>
          <xsl:when test="contains(value, 'cpe:/o:starnet')">
            <xsl:text>
              <!-- TODO classify xwin32 -->
            </xsl:text>
          </xsl:when>
          <xsl:when test="contains(value, 'cpe:/o:sun')">
            <xsl:text>gsm_system_unix </xsl:text>
          </xsl:when>
          <xsl:when test="contains(value, 'cpe:/o:suse')">
            <xsl:text>gsm_system_unix gsm_system_linux </xsl:text>
          </xsl:when>
          <xsl:when test="contains(value, 'cpe:/o:trustix')">
            <xsl:text>gsm_system_unix </xsl:text>
          </xsl:when>
          <xsl:when test="contains(value, 'cpe:/o:univention')">
            <xsl:text>gsm_system_unix gsm_system_linux </xsl:text>
          </xsl:when>
          <xsl:when test="contains(value, 'cpe:/o:vmware')">
            <xsl:text>
              <!-- TODO -->
            </xsl:text>
          </xsl:when>
          <xsl:when test="contains(value, 'cpe:/o:windriver')">
            <xsl:text>
              <!-- TODO -->
            </xsl:text>
          </xsl:when>
          <xsl:when test="contains(value, 'cpe:/o:yamaha')">
            <xsl:text>
              <!-- TODO -->
            </xsl:text>
          </xsl:when>
        </xsl:choose>
      </xsl:when>
      <!-- Check for other cpe details -->
      <xsl:when test="name='App'">
        <xsl:if test="$include_apps">
          <xsl:choose>
            <xsl:when test="contains(value, 'cpe:/a:apache:http_server')">
              <xsl:text>gsm_system_apache gsm_system_wwwserver </xsl:text>
            </xsl:when>
            <xsl:when test="contains(value, 'cpe:/a:microsoft:iis')">
              <xsl:text>gsm_system_iis gsm_system_wwwserver </xsl:text>
            </xsl:when>
            <xsl:when test="contains(value, 'cpe:/a:microsoft:exchange_server')">
              <xsl:text>gsm_system_exchange </xsl:text>
            </xsl:when>
            <xsl:when test="contains(value, 'cpe:/a:microsoft:outlook')">
              <xsl:text>gsm_system_outlook </xsl:text>
            </xsl:when>
            <xsl:when test="contains(value, 'cpe:/a:ibm:lotus_notes')">
              <xsl:text>gsm_system_notes </xsl:text>
            </xsl:when>
            <xsl:when test="contains(value, 'cpe:/a:sap:')">
              <xsl:text>gsm_system_sap </xsl:text>
            </xsl:when>
            <xsl:when test="contains(value, 'cpe:/a:samba:samba')">
              <xsl:text>gsm_system_samba </xsl:text>
            </xsl:when>
          </xsl:choose>
        </xsl:if>
      </xsl:when>
    </xsl:choose>
  </xsl:template>

  <!-- Remove duplicated elements from the string list -->
  <xsl:template name="remove-duplicates">
    <xsl:param name="string"/>
    <xsl:param name="newstring"/>
    <xsl:choose>
      <xsl:when test="$string = ''">
        <xsl:value-of select="$newstring"/>
      </xsl:when>
      <xsl:otherwise>
        <xsl:if test="contains($newstring, substring-before($string, ' '))">
          <xsl:call-template name="remove-duplicates">
            <xsl:with-param name="string" select="substring-after($string, ' ')"/>
            <xsl:with-param name="newstring" select="$newstring"/>
          </xsl:call-template>
        </xsl:if>
        <xsl:if test="not(contains($newstring, substring-before($string, ' ')))">
          <xsl:variable name="temp">
            <xsl:if test="$newstring = ''">
              <xsl:value-of select="substring-before($string, ' ')"/>
            </xsl:if>
            <xsl:if test="not($newstring = '')">
              <xsl:value-of select="concat($newstring, ' ', substring-before($string, ' '))"/>
            </xsl:if>
          </xsl:variable>
          <xsl:call-template name="remove-duplicates">
            <xsl:with-param name="string" select="substring-after($string, ' ')"/>
            <xsl:with-param name="newstring" select="$temp"/>
          </xsl:call-template>
        </xsl:if>
      </xsl:otherwise>
    </xsl:choose>
</xsl:template>

<xsl:template name="extract_organization">
    <xsl:choose>
        <!-- TODO enter here the real path of the organization tag -->
        <xsl:when test="string-length(report/task/tags/organization) &gt; 0">
            <xsl:value-of select="report/task/tags/organization"/>
        </xsl:when>
        <xsl:when test="string-length(report/task/comment) &gt; 0">
            <xsl:value-of select="report/task/comment"/>
        </xsl:when>
        <xsl:otherwise>
            <xsl:value-of select="report/task/name"/>
        </xsl:otherwise>
    </xsl:choose>
</xsl:template>
</xsl:stylesheet>

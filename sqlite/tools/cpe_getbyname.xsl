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

<!-- Select a CPE item by name. -->
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:scap-core="http://scap.nist.gov/schema/scap-core/0.3"
  xmlns:meta="http://scap.nist.gov/schema/cpe-dictionary-metadata/0.2"
  xmlns:ns6="http://scap.nist.gov/schema/scap-core/0.1"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xmlns:config="http://scap.nist.gov/schema/configuration/0.1"
  xmlns:cpe="http://cpe.mitre.org/dictionary/2.0"
  xsi:schemaLocation="http://scap.nist.gov/schema/configuration/0.1 http://nvd.nist.gov/schema/configuration_0.1.xsd http://scap.nist.gov/schema/scap-core/0.3 http://nvd.nist.gov/schema/scap-core_0.3.xsd http://cpe.mitre.org/dictionary/2.0 http://cpe.mitre.org/files/cpe-dictionary_2.2.xsd http://scap.nist.gov/schema/scap-core/0.1 http://nvd.nist.gov/schema/scap-core_0.1.xsd http://scap.nist.gov/schema/cpe-dictionary-metadata/0.2 http://nvd.nist.gov/schema/cpe-dictionary-metadata_0.2.xsd">

<xsl:output method="html"/>

<xsl:template match="cpe:cpe-list">
  <xsl:choose>
    <xsl:when test="count(cpe:cpe-item[@name = $refname]) &gt; 0">
      <xsl:copy-of select="cpe:cpe-item[@name = $refname]"/>
    </xsl:when>
    <xsl:otherwise>
      <!--
        Return an empty item if nothing was found. This CPE is probably
        referenced by a CVE but not in the official dictionary yet.
      -->
      <cpe-item xmlns:scap-core="http://scap.nist.gov/schema/scap-core/0.3"
                xmlns:meta="http://scap.nist.gov/schema/cpe-dictionary-metadata/0.2"
                xmlns:ns6="http://scap.nist.gov/schema/scap-core/0.1"
                xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                xmlns:config="http://scap.nist.gov/schema/configuration/0.1"
                xmlns="http://cpe.mitre.org/dictionary/2.0" name="{$refname}"/>
    </xsl:otherwise>
  </xsl:choose>
</xsl:template>

</xsl:stylesheet>


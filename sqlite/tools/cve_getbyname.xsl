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

<!-- Select a CVE item by name. -->

<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:vuln="http://scap.nist.gov/schema/vulnerability/0.4"
  xmlns:cpe-lang="http://cpe.mitre.org/language/2.0"
  xmlns:scap-core="http://scap.nist.gov/schema/scap-core/0.1"
  xmlns:cve="http://scap.nist.gov/schema/feed/vulnerability/2.0"
  xmlns:cvss="http://scap.nist.gov/schema/cvss-v2/0.2"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xmlns:patch="http://scap.nist.gov/schema/patch/0.1">

<xsl:output method="html"/>

<xsl:template match="cve:nvd">
  <xsl:copy-of select="cve:entry[@id = $refname]"/>
</xsl:template>

</xsl:stylesheet>


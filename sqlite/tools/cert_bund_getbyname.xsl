<?xml version="1.0" encoding="UTF-8"?>
<!--
Copyright (C) 2013-2018 Greenbone Networks GmbH

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

<!--Select a DFN-CERT item by name. -->

<xsl:stylesheet version="1.0" 
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:ns6="http://scap.nist.gov/schema/scap-core/0.1"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xmlns:str="http://exslt.org/strings"
  xmlns:dfncert="http://www.dfn-cert.de/dfncert.dtd"
  xmlns:atom="http://www.w3.org/2005/Atom"
  extension-element-prefixes="str"
  >

<xsl:output method="html"/>

<xsl:template match="/">
  <xsl:copy-of select="//Advisory[Ref_Num = $refname]"/>
</xsl:template>

</xsl:stylesheet>


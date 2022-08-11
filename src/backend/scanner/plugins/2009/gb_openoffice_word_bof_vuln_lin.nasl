###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openoffice_word_bof_vuln_lin.nasl 12629 2018-12-03 15:19:43Z cfischer $
#
# OpenOffice.org Word Documents Parsing Buffer Overflow Vulnerability (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800695");
  script_version("$Revision: 12629 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-03 16:19:43 +0100 (Mon, 03 Dec 2018) $");
  script_tag(name:"creation_date", value:"2009-09-08 18:25:53 +0200 (Tue, 08 Sep 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0200", "CVE-2009-0201");
  script_bugtraq_id(36200);
  script_name("OpenOffice.org Word Documents Parsing Buffer Overflow Vulnerability (Linux)");
  script_xref(name:"URL", value:"http://secunia.com/secunia_research/2009-27/");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/2490");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_openoffice_detect_lin.nasl");
  script_mandatory_keys("OpenOffice/Linux/Ver");
  script_tag(name:"impact", value:"Successful remote exploitation could result in arbitrary code execution on
  the affected system which leads to application crash and compromise a
  vulnerable system.");
  script_tag(name:"affected", value:"OpenOffice Version prior to 3.1.1 on Linux.");
  script_tag(name:"insight", value:"- An integer underflow error occurs when parsing certain records in a
    Word document table.

  - An heap overflow error occurs when parsing certain records in a Word
    document when opening a malicious Word document.");
  script_tag(name:"solution", value:"Upgrade to OpenOffice Version 3.1.1 or later");
  script_tag(name:"summary", value:"The host has OpenOffice installed and is prone to Buffer
  Overflow vulnerability.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.openoffice.org/");
  exit(0);
}


include("version_func.inc");

openVer = get_kb_item("OpenOffice/Linux/Ver");
if(!openVer)
{
  exit(0);
}

if(version_is_less(version:openVer, test_version:"3.1.1")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

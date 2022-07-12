###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_novell_zhm_bof_vuln.nasl 12674 2018-12-05 15:13:45Z cfischer $
#
# Novell ZENworks Handheld Management 'ZfHIPCND.exe' Buffer Overflow Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801645");
  script_version("$Revision: 12674 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-05 16:13:45 +0100 (Wed, 05 Dec 2018) $");
  script_tag(name:"creation_date", value:"2010-11-30 12:42:12 +0100 (Tue, 30 Nov 2010)");
  script_bugtraq_id(44700);
  script_cve_id("CVE-2010-4299");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Novell ZENworks Handheld Management 'ZfHIPCND.exe' Buffer Overflow Vulnerability");

  script_xref(name:"URL", value:"http://secunia.com/advisories/42130");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id?1024691");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-230/");
  script_xref(name:"URL", value:"http://www.novell.com/support/viewContent.do?externalId=7007135");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_novell_zhm_detect.nasl");
  script_mandatory_keys("Novell/ZHM/Ver");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute arbitrary
  code with SYSTEM privileges or cause denial of service.");

  script_tag(name:"affected", value:"Novell ZENworks Handheld Management 7");

  script_tag(name:"insight", value:"The flaw exists within module 'ZfHIPCND.exe', which allows remote attackers
  to execute arbitrary code via a crafted request to TCP port 2400.");

  script_tag(name:"summary", value:"This host is installed with Novell ZENworks Handheld Management
  and is prone to buffer overflow vulnerability.");

  script_tag(name:"solution", value:"Apply the patch, available via the referenced links.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://download.novell.com/Download?buildid=Sln2Lkqslmk~");

  exit(0);
}

include("version_func.inc");

zhmVer = get_kb_item("Novell/ZHM/Ver");

if(zhmVer)
{
  if(version_in_range(version:zhmVer, test_version:"7.0", test_version2:"7.0.2.61213")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}

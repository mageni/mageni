###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_prdts_jsinfer_dos_vuln_macosx.nasl 11818 2018-10-10 11:35:42Z asteins $
#
# Mozilla Products 'jsinfer.cpp' Denial of Service Vulnerability (Mac OS X)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802870");
  script_version("$Revision: 11818 $");
  script_cve_id("CVE-2012-1939");
  script_bugtraq_id(53797);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-10 13:35:42 +0200 (Wed, 10 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-06-19 15:21:15 +0530 (Tue, 19 Jun 2012)");
  script_name("Mozilla Products 'jsinfer.cpp' Denial of Service Vulnerability (Mac OS X)");

  script_xref(name:"URL", value:"http://secunia.com/advisories/49368");
  script_xref(name:"URL", value:"http://secunia.com/advisories/49366");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1027120");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-34.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Mac/Installed");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code in
  the context of the browser or cause a denial of service.");
  script_tag(name:"affected", value:"Thunderbird ESR version 10.x before 10.0.5,
  Mozilla Firefox ESR version 10.x before 10.0.5 on Mac OS X");
  script_tag(name:"insight", value:"The 'jsinfer.cpp' function in ESR versions fails to determine data types,
  which allows to cause a denial of service via crafted JavaScript code.");
  script_tag(name:"summary", value:"This host is installed with Mozilla firefox/thunderbird and is prone to
  denial of service vulnerability.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox ESR version 10.0.5 or later.

  Upgrade to Mozilla Thunderbird ESR version 10.0.5 or later.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.mozilla.com/en-US/firefox/all.html");
  script_xref(name:"URL", value:"http://www.mozilla.com/en-US/thunderbird");

  exit(0);
}


include("version_func.inc");

ffVer = get_kb_item("Mozilla/Firefox/MacOSX/Version");

if(ffVer)
{
  if(version_in_range(version:ffVer, test_version:"10.0", test_version2:"10.0.4"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

tbVer = get_kb_item("ThunderBird/MacOSX/Version");

if(tbVer)
{
  if(version_in_range(version:tbVer, test_version:"10.0", test_version2:"10.0.4"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

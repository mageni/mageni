###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_air_mult_vuln01_feb13_macosx.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# Adobe AIR Multiple Vulnerabilities -01 Feb13 (Mac OS X)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803411");
  script_version("$Revision: 11865 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-02-15 11:14:45 +0530 (Fri, 15 Feb 2013)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2013-0637", "CVE-2013-0638", "CVE-2013-0639", "CVE-2013-0642",
                "CVE-2013-0644", "CVE-2013-0645", "CVE-2013-0647", "CVE-2013-0649",
                "CVE-2013-1365", "CVE-2013-1366", "CVE-2013-1367", "CVE-2013-1368",
                "CVE-2013-1369", "CVE-2013-1370", "CVE-2013-1372", "CVE-2013-1373",
                "CVE-2013-1374");
  script_bugtraq_id(57929, 57926, 57925, 57923, 57933, 57916, 57927, 57930, 57920,
                    57924, 57922, 57918, 57919, 57912, 57917);
  script_name("Adobe AIR Multiple Vulnerabilities -01 Feb13 (Mac OS X)");
  script_xref(name:"URL", value:"https://lwn.net/Articles/537746");
  script_xref(name:"URL", value:"http://secunia.com/advisories/52166");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb13-05.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Air/MacOSX/Version");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause buffer
  overflow, remote code execution and corrupt system memory.");

  script_tag(name:"affected", value:"Adobe AIR Version prior to 3.6.0.597 on Mac OS X");

  script_tag(name:"insight", value:"Multiple flaws due to

  - Dereference already freed memory

  - Use-after-free errors

  - Integer overflow and some unspecified error.");

  script_tag(name:"solution", value:"Update to version 3.6.0.597 or later.");

  script_tag(name:"summary", value:"This host is installed with Adobe AIR and is prone to multiple
  vulnerabilities.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://get.adobe.com/air");
  exit(0);
}

include("version_func.inc");

playerVer = get_kb_item("Adobe/Air/MacOSX/Version");
if(playerVer != NULL)
{
  if(version_is_less(version:playerVer, test_version:"3.6.0.597"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

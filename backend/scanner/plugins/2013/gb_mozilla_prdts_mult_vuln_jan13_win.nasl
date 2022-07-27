###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_prdts_mult_vuln_jan13_win.nasl 11866 2018-10-12 10:12:29Z cfischer $
#
# Mozilla Products Multiple Vulnerabilities January13 (Windows)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.803098");
  script_version("$Revision: 11866 $");
  script_cve_id("CVE-2013-0744", "CVE-2013-0746", "CVE-2013-0748", "CVE-2013-0750",
                "CVE-2013-0753", "CVE-2013-0754", "CVE-2013-0758", "CVE-2013-0759");
  script_bugtraq_id(57218, 57238, 57234, 57235, 57209, 57217, 57232, 57228);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:12:29 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-01-16 15:08:04 +0530 (Wed, 16 Jan 2013)");
  script_name("Mozilla Products Multiple Vulnerabilities January13 (Windows)");

  script_xref(name:"URL", value:"http://secunia.com/advisories/51752/");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1027955");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1027957");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1027958");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-04.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-05.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-09.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-11.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-12.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-15.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-16.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-17.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl", "gb_seamonkey_detect_win.nasl", "gb_thunderbird_detect_portable_win.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to inject scripts, bypass
  certain security restrictions, execute arbitrary code or crash the
  application in the context of the browser.");
  script_tag(name:"affected", value:"SeaMonkey version before 2.15 on Windows
  Thunderbird version before 17.0.2 on Windows
  Mozilla Firefox version before 18.0 on Windows
  Thunderbird ESR version 10.x before 10.0.12 and 17.x before 17.0.2 on Windows
  Mozilla Firefox ESR version 10.x before 10.0.12 and 17.x before 17.0.2 on Windows");
  script_tag(name:"insight", value:"- URL spoofing in address bar during page loads in conjunction with a
    204 (aka No Content) HTTP status code.

  - Improper interaction between plugin objects and SVG elements.

  - Use-after-free error exists within the implementation serializeToStream
    in the XMLSerializer component and ListenerManager, and in the function
   'TableBackgroundPainter::TableBackgroundData::Destroy'.
    'serializeToStream' implementation in the XMLSerializer component

  - Compartment mismatch with quickstubs returned values.

  - An error within the 'XBL.__proto__.toString()' can be exploited to
    disclose the address space layout.");
  script_tag(name:"summary", value:"This host is installed with Mozilla Firefox/Thunderbird/Seamonkey and is
  prone to multiple vulnerabilities.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 18.0 or ESR version 10.0.12 or 17.0.2 or later, upgrade to SeaMonkey version to 2.15 or later,
  upgrade to Thunderbird version to 17.0.2 or ESR 10.0.12 or 17.0.2 or later.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.mozilla.com/en-US/firefox/all.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/projects/seamonkey/");
  script_xref(name:"URL", value:"http://www.mozilla.org/en-US/thunderbird/");

  exit(0);
}

include("version_func.inc");

ffVer = get_kb_item("Firefox/Win/Ver");
fesrVer = get_kb_item("Firefox-ESR/Win/Ver");

if(ffVer || fesrVer)
{
  if(version_is_less(version:ffVer, test_version:"18.0")||
     version_in_range(version:fesrVer, test_version:"10.0", test_version2:"10.0.11")||
     version_in_range(version:fesrVer, test_version:"17.0", test_version2:"17.0.1"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

seaVer = get_kb_item("Seamonkey/Win/Ver");
if(seaVer)
{
  if(version_is_less(version:seaVer, test_version:"2.15"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

tbVer = get_kb_item("Thunderbird/Win/Ver");
tbesrVer = get_kb_item("Thunderbird-ESR/Win/Ver");

if(tbVer || tbesrVer)
{
  if(version_is_less(version:tbVer, test_version:"17.0.2")||
     version_in_range(version:tbesrVer, test_version:"10.0", test_version2:"10.0.11")||
     version_in_range(version:tbesrVer, test_version:"17.0", test_version2:"17.0.1"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

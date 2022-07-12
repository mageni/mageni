###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sea_monkey_mult_vuln01_feb14_win.nasl 35149 2014-02-11 19:41:13Z feb$
#
# SeaMonkey Multiple Vulnerabilities-01 Feb14 (Windows)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:mozilla:seamonkey";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804094");
  script_version("$Revision: 11867 $");
  script_cve_id("CVE-2014-1477", "CVE-2014-1478", "CVE-2014-1479", "CVE-2014-1480",
                "CVE-2014-1481", "CVE-2014-1482", "CVE-2014-1483", "CVE-2014-1485",
                "CVE-2014-1486", "CVE-2014-1487", "CVE-2014-1488", "CVE-2014-1490",
                "CVE-2014-1491");
  script_bugtraq_id(65317, 65324, 65320, 65331, 65326, 65328, 65316, 65322,
                    65334, 65330, 65321, 65335, 65332);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-02-11 19:41:13 +0530 (Tue, 11 Feb 2014)");
  script_name("SeaMonkey Multiple Vulnerabilities-01 Feb14 (Windows)");


  script_tag(name:"summary", value:"This host is installed with SeaMonkey and is prone to multiple
vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Multiple flaws are due to,

  - An error when handling XML Binding Language (XBL) content scopes.

  - An error when handling discarded images within the 'RasterImage' class.

  - An error related to the 'document.caretPositionFromPoint()' and
  'document.elementFromPoint()' functions.

  - An error when handling XSLT stylesheets.

  - A use-after-free error related to certain content types when used with the
  'imgRequestProxy()' function.

  - An error when handling web workers error messages.

  - An error when terminating a web worker running asm.js code after passing an
  object between threads.

  - A race condition error when handling session tickets within libssl.

  - An error when handling JavaScript native getters on window objects.

  - Additionally, a weakness exists when handling the dialog for saving downloaded
  files.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to bypass certain security
restrictions and compromise a user's system.");
  script_tag(name:"affected", value:"SeaMonkey version before 2.24 on Windows");
  script_tag(name:"solution", value:"Upgrade to SeaMonkey version 2.24 or later.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/56767");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-01.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_seamonkey_detect_win.nasl");
  script_mandatory_keys("Seamonkey/Win/Ver");
  script_xref(name:"URL", value:"http://www.mozilla.com/en-US/seamonkey");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!smVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:smVer, test_version:"2.24"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}

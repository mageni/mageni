###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_safari_webkit_mult_vuln_dec14_macosx.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# Apple Safari 'Webkit' Multiple Vulnerabilities-01 Dec14 (Mac OS X)
#
# Authors:
# Deependra Bapna <bdeependra@secpod.com>
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

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805305");
  script_version("$Revision: 11867 $");
  script_cve_id("CVE-2014-4475", "CVE-2014-4474", "CVE-2014-4473", "CVE-2014-4472",
                "CVE-2014-4471", "CVE-2014-4470", "CVE-2014-4469", "CVE-2014-4468",
                "CVE-2014-4466", "CVE-2014-4465");
  script_bugtraq_id(71451, 71449, 71444, 71442, 71438, 71462, 71461, 71459,
                    71445, 71439);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-12-16 14:55:53 +0530 (Tue, 16 Dec 2014)");
  script_name("Apple Safari 'Webkit' Multiple Vulnerabilities-01 Dec14 (Mac OS X)");

  script_tag(name:"summary", value:"This host is installed with Apple Safari
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - Multiple unspecified memory corruption errors.

  - An SVG loaded in an img element could load a CSS file cross-origin.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to conduct denial of service attack, arbitrary code execution and bypass the
  Same Origin Policy.");

  script_tag(name:"affected", value:"Apple Safari before version 6.2.1,
  7.x before 7.1.1, and 8.x before 8.0.1 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Apple Safari version 6.2.1 or
  7.1.1 or 8.0.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://support.apple.com/kb/HT6145");
  script_xref(name:"URL", value:"http://secunia.com/advisories/57093");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/125428");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("macosx_safari_detect.nasl");
  script_mandatory_keys("AppleSafari/MacOSX/Version");
  script_xref(name:"URL", value:"http://www.apple.com/support");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!safVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:safVer, test_version:"6.2.1") ||
   version_in_range(version:safVer, test_version:"7.0", test_version2:"7.1.0")||
   version_is_equal(version:safVer, test_version:"8.0"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}

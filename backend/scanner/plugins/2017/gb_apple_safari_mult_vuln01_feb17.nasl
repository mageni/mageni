###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_safari_mult_vuln01_feb17.nasl 12391 2018-11-16 16:12:15Z cfischer $
#
# Apple Safari Multiple Vulnerabilities-01 February17
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.810564");
  script_version("$Revision: 12391 $");
  script_cve_id("CVE-2017-2359", "CVE-2017-2350", "CVE-2017-2362", "CVE-2017-2373",
                "CVE-2017-2354", "CVE-2017-2355", "CVE-2017-2356", "CVE-2017-2366",
                "CVE-2017-2369", "CVE-2017-2363", "CVE-2017-2364", "CVE-2017-2365");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 17:12:15 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-02-22 14:46:57 +0530 (Wed, 22 Feb 2017)");
  script_name("Apple Safari Multiple Vulnerabilities-01 February17");

  script_tag(name:"summary", value:"This host is installed with Apple Safari
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - A state management issue in the address bar.

  - A prototype access issue in WebKit

  - Multiple memory corruption issues in WebKit.

  - A memory initialization issue in WebKit.

  - Multiple validation issues existed in the handling of page loading in WebKit.

  - A validation issue existed in variable handling in WebKit.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to spoof the address bar, bypass security restrictions and obtain
  sensitive information, execute arbitrary code or cause a denial of service.");

  script_tag(name:"affected", value:"Apple Safari versions before 10.0.3");

  script_tag(name:"solution", value:"Upgrade to Apple Safari version 10.0.3 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT207484");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
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

if(version_is_less(version:safVer, test_version:"10.0.3"))
{
  report = report_fixed_ver(installed_version:safVer, fixed_version:"10.0.3");
  security_message(data:report);
  exit(0);
}

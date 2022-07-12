###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_icloud_mult_vuln_feb17.nasl 11888 2018-10-12 15:27:49Z cfischer $
#
# Apple iCloud Multiple Vulnerabilities Feb17 (Windows)
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
CPE = "cpe:/a:apple:icloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810576");
  script_version("$Revision: 11888 $");
  script_cve_id("CVE-2016-4692", "CVE-2016-7635", "CVE-2016-7652", "CVE-2016-7656",
                "CVE-2016-4743", "CVE-2016-7586", "CVE-2016-7587", "CVE-2016-7610",
                "CVE-2016-7611", "CVE-2016-7639", "CVE-2016-7640", "CVE-2016-7641",
                "CVE-2016-7642", "CVE-2016-7645", "CVE-2016-7646", "CVE-2016-7648",
                "CVE-2016-7649", "CVE-2016-7654", "CVE-2016-7589", "CVE-2016-7592",
                "CVE-2016-7598", "CVE-2016-7599", "CVE-2016-7632", "CVE-2016-7614");
  script_bugtraq_id(95736, 95733);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 17:27:49 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-02-28 10:49:30 +0530 (Tue, 28 Feb 2017)");
  script_name("Apple iCloud Multiple Vulnerabilities Feb17 (Windows)");

  script_tag(name:"summary", value:"This host is installed with Apple iCloud
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Multiple memory corruption errors in WebKit.

  - A validation error in WebKit.

  - An error in handling of JavaScript prompts.

  - An error in the handling of HTTP redirects.

  - The iCloud desktop client failed to clear sensitive information in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code, cause unexpected application termination
  and disclose sensitive information.");

  script_tag(name:"affected", value:"Apple iCloud versions before 6.1
  on Windows.");

  script_tag(name:"solution", value:"Upgrade to Apple iCloud 6.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT207424");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_apple_icloud_detect_win.nasl");
  script_mandatory_keys("apple/icloud/Win/Ver");
  script_xref(name:"URL", value:"http://www.apple.com/in/icloud/setup/pc.html");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!icVer = get_app_version(cpe:CPE)){
  exit(0);
}

##  Check for Apple iCloud vulnerable versions
if(version_is_less(version:icVer, test_version:"6.1"))
{
  report = report_fixed_ver(installed_version:icVer, fixed_version:"6.1");
  security_message(data:report);
  exit(0);
}

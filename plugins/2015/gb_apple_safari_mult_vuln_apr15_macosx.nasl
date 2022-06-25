###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_safari_mult_vuln_apr15_macosx.nasl 14319 2019-03-19 11:49:19Z cfischer $
#
# Apple Safari Multiple Vulnerabilities -01 Apr15 (Mac OS X)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805467");
  script_version("$Revision: 14319 $");
  script_cve_id("CVE-2015-1112", "CVE-2015-1119", "CVE-2015-1120", "CVE-2015-1121",
                "CVE-2015-1122", "CVE-2015-1124", "CVE-2015-1126", "CVE-2015-1127",
                "CVE-2015-1128", "CVE-2015-1129");
  script_bugtraq_id(73972, 73973, 73974, 73975, 73976, 73977);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 12:49:19 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-04-23 17:30:41 +0530 (Thu, 23 Apr 2015)");
  script_name("Apple Safari Multiple Vulnerabilities -01 Apr15 (Mac OS X)");

  script_tag(name:"summary", value:"This host is running Apple Safari and is
  prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - a flaw in client certificate matching during SSL authentication.

  - a flaw in private browsing mode that is triggered when responding to push
  notification requests.

  - a flaw in  loader/icon/IconController.cpp script in WebKit as URLs visited
  during private browsing are stored in WebpageIcons.db.

  - An unspecified state management issue in apple safari.

  - A flaw in WebKit that is triggered as user-supplied input is not properly
  validated.

  - A flaw in WebKit that is triggered when handling credentials for FTP URLs.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attacker to unexpectedly gain knowledge of sites visited during private
  browsing, context-dependent attacker to track a user's web traffic and gain
  access to a user's browsing history, potentially execute arbitrary code, to
  access cross-origin resources, cause a user's browser history to not be
  completely purged from history.plist.");

  script_tag(name:"affected", value:"Apple Safari versions before 6.2.5, 7.x
  before 7.1.5 and 8.x before 8.0.5");

  script_tag(name:"solution", value:"Upgrade to Apple Safari version 6.2.5 or
  7.1.5 or 8.0.5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"http://support.apple.com/en-us/HT204658");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2015/Apr/msg00000.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("macosx_safari_detect.nasl");
  script_mandatory_keys("AppleSafari/MacOSX/Version");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!safVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:safVer, test_version:"6.2.5"))
{
  fix = "6.2.5";
  VULN = TRUE;
}

if(version_in_range(version:safVer, test_version:"7.0", test_version2:"7.1.4"))
{
  fix = "7.1.5";
  VULN = TRUE;
}

if(version_in_range(version:safVer, test_version:"8.0", test_version2:"8.0.4"))
{
  fix = "8.0.5";
  VULN = TRUE;
}

if(VULN)
{
  report = 'Installed version: ' + safVer + '\n' +
           'Fixed version:     ' + fix + '\n';
  security_message(data:report);
  exit(0);
}

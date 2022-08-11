###############################################################################
# OpenVAS Vulnerability Test
#
# Python Multiple Denial of Service Vulnerabilities June18 (Mac OS X)
#
# Authors:
# Rajat Mishra <rajatm@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:python:python";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813547");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-1060", "CVE-2018-1061");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-06-28 18:47:01 +0530 (Thu, 28 Jun 2018)");
  script_name("Python Multiple Denial of Service Vulnerabilities June18 (Mac OS X)");

  script_tag(name:"summary", value:"This host is installed with python and is
  prone to multiple denial of service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Failing to sanitize against backtracking in pop3lib's apop method.

  - Failing to sanitize against backtracking in 'difflib.IS_LINE_JUNK' method.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to conduct denial of service attack on the affected user.");

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"affected", value:"Python before versions 2.7.15, 3.4.9, 3.5.6
  and 3.7.0.beta3 on Mac OS X");

  script_tag(name:"solution", value:"Upgrade to Python 2.7.15 or 3.4.9 or 3.5.6
  or 3.7.0.beta3. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugs.python.org/issue32981");
  script_xref(name:"URL", value:"https://docs.python.org/3.6/whatsnew/changelog.html");
  script_xref(name:"URL", value:"https://docs.python.org/3.7/whatsnew/changelog.html");
  script_xref(name:"URL", value:"https://www.python.org");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_python_detect_macosx.nasl");
  script_mandatory_keys("python/MacOSX/Version");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
pVer = infos['version'];
pPath = infos['location'];

##2.7.15 == 2.7.15150
if(version_is_less(version:pVer, test_version:"2.7.15150")){
  fix = "2.7.15";
}

#Versions 3.4.9 and 3.5.6 can't be verified because of unavailability of downloads
#else if(version_in_range(version: pVer, test_version: "3.4.0", test_version2: "3.4.16789"))
#{
#  report = report_fixed_ver(installed_version:pVer, fixed_version:"3.4.9", install_path:pPath);
#  security_message(data:report);
#  exit(0);
#}
#
#else if(version_in_range(version: pVer, test_version: "3.5.0", test_version2: "3.5.4121.0"))
#{
#  report = report_fixed_ver(installed_version:pVer, fixed_version:"3.5.6", install_path:pPath);
#  security_message(data:report);
#  exit(0);
#}

#Version 3.6.4 = 3.6.4150.0
else if(version_in_range(version: pVer, test_version: "3.6.0", test_version2: "3.6.4150.0")){
  fix = "3.6.5";
}

#Version 3.7.0.b3 = 3.7.133.0
else if(version_is_greater(version: pVer, test_version: "3.7.0") && version_is_less(version: pVer, test_version: "3.7.133.0")){
  fix = "3.7.0 beta 3";
}

if(fix)
{
  report = report_fixed_ver(installed_version:pVer, fixed_version:fix, install_path:pPath);
  security_message(data:report);
  exit(0);
}
exit(0);

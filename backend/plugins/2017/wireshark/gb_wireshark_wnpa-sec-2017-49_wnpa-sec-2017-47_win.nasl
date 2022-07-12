###############################################################################
# OpenVAS Vulnerability Test
#
# Wireshark Security Updates (wnpa-sec-2017-49_wnpa-sec-2017-47)-Windows
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

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812259");
  script_version("2019-05-17T13:14:58+0000");
  script_cve_id("CVE-2017-17083", "CVE-2017-17084", "CVE-2017-17085");
  script_bugtraq_id(102029, 102030, 102071);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2019-05-17 13:14:58 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2017-12-15 11:37:23 +0530 (Fri, 15 Dec 2017)");
  script_name("Wireshark Security Updates (wnpa-sec-2017-49_wnpa-sec-2017-47)-Windows");

  script_tag(name:"summary", value:"This host is installed with Wireshark
  and is prone to multiple denial of service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to multiple errors
  in 'NetBIOS', 'IWARP_MPA' and 'CIP Safety' dissectors, which fails to properly
  handle certain types of packets.");

  script_tag(name:"impact", value:"Successful exploitation of these
  vulnerabilities will allow remote attackers to crash the affected application,
  denying service to legitimate users.");

  script_tag(name:"affected", value:"Wireshark version 2.4.0 to 2.4.2, 2.2.0
  to 2.2.10 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Wireshark version 2.4.3 or
  2.2.11 or later.");

  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-47.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-48.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-49.html");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_mandatory_keys("Wireshark/Win/Ver");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
wirversion = infos['version'];
path = infos['location'];

if(wirversion =~ "^2\.[24]\.")
{
  if(version_in_range(version:wirversion, test_version:"2.4.0", test_version2:"2.4.2")){
    fix = "2.4.3";
  }

  else if(version_in_range(version:wirversion, test_version:"2.2.0", test_version2:"2.2.10")){
    fix = "2.2.11";
  }

  if(fix)
  {
    report = report_fixed_ver(installed_version:wirversion, fixed_version:fix, install_path:path);
    security_message(data:report);
    exit(0);
  }
}
exit(0);

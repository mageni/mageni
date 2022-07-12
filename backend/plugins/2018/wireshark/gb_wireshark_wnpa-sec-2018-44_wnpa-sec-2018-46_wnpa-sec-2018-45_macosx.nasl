###############################################################################
# OpenVAS Vulnerability Test
#
# Wireshark Security Updates (wnpa-sec-2018-44_wnpa-sec-2018-46_wnpa-sec-2018-45) MACOSX
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813882");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-16058", "CVE-2018-16057", "CVE-2018-16056");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-08-31 15:44:50 +0530 (Fri, 31 Aug 2018)");
  script_name("Wireshark Security Updates (wnpa-sec-2018-44_wnpa-sec-2018-46_wnpa-sec-2018-45) MACOSX");

  script_tag(name:"summary", value:"This host is installed with Wireshark
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - A missing validation for iterator operations in 'epan/dissectors/packet-ieee80211-radiotap-iter.c'
    script.

  - An improper initialization of a data structure in 'epan/dissectors/packet-btavdtp.c'
    script.

  - An improper handling of UUID in 'epan/dissectors/packet-btatt.c' script.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to crash the affected application or to consume excess memory, denying service
  to legitimate users.");

  script_tag(name:"affected", value:"Wireshark version 2.6.0 to 2.6.2, 2.4.0 to
  2.4.8 and 2.2.0 to 2.2.16 on Macosx.");

  script_tag(name:"solution", value:"Upgrade to Wireshark version 2.6.3, 2.4.9 or
  2.2.17 or later. Please see the references for more information.");

  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2018-44");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2018-46");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2018-45");
  script_xref(name:"URL", value:"https://www.wireshark.org");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_wireshark_detect_macosx.nasl");
  script_mandatory_keys("Wireshark/MacOSX/Version");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
wirversion = infos['version'];
path = infos['location'];

if(version_in_range(version:wirversion, test_version:"2.6.0", test_version2:"2.6.2")){
  fix = "2.6.3";
}

else if(version_in_range(version:wirversion, test_version:"2.4.0", test_version2:"2.4.8")){
  fix = "2.4.9";
}

else if(version_in_range(version:wirversion, test_version:"2.2.0", test_version2:"2.2.16")){
  fix = "2.2.17";
}

if(fix)
{
  report = report_fixed_ver(installed_version:wirversion, fixed_version:fix, install_path:path);
  security_message(data:report);
  exit(0);
}
exit(0);

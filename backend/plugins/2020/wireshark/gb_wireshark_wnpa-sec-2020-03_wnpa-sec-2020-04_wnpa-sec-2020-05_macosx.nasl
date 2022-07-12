# Copyright (C) 2020 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815782");
  script_version("2020-03-03T12:05:12+0000");
  script_cve_id("CVE-2020-9431", "CVE-2020-9430", "CVE-2020-9428");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2020-03-03 12:05:12 +0000 (Tue, 03 Mar 2020)");
  script_tag(name:"creation_date", value:"2020-03-03 15:04:47 +0530 (Tue, 03 Mar 2020)");
  script_name("Wireshark Security Updates (wnpa-sec-2020-03_wnpa-sec-2020-04_wnpa-sec-2020-05) Mac OS X");

  script_tag(name:"summary", value:"This host is installed with Wireshark
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaws exist due to

  - An uncontrolled resource consumption issue in LTE RRC dissector.

  - An improper input validation issue in WiMax DLMAP dissector.

  - An improper neutralization issue in  EAP dissector.");

  script_tag(name:"impact", value:"Successful exploitation allows attackers
  to crash Wireshark by injecting a malformed packet onto the wire or by
  convincing someone to read a malformed packet trace file.");

  script_tag(name:"affected", value:"Wireshark version 2.6.0 to 2.6.14,
  3.0.0 to 3.0.8, and 3.2.0 to 3.2.1 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Wireshark version 2.6.15, 3.0.9,
  or 3.2.2. Please see the references for more information.");

  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2020-03.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2020-04.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2020-05.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
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

if(version_in_range(version:wirversion, test_version:"2.6.0", test_version2:"2.6.14")){
  fix = "2.6.15";
}

else if(version_in_range(version:wirversion, test_version:"3.0.0", test_version2:"3.0.8")){
  fix = "3.0.9";
}

else if(version_in_range(version:wirversion, test_version:"3.2.0", test_version2:"3.2.1")){
  fix = "3.2.2";
}

if(fix)
{
  report = report_fixed_ver(installed_version:wirversion, fixed_version:fix);
  security_message(data:report);
  exit(0);
}
exit(99);

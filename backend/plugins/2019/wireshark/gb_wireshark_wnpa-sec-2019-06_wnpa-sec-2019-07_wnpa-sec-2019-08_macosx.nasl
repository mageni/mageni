# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.814867");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2019-9208", "CVE-2019-9209", "CVE-2019-9214");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2019-02-28 11:33:48 +0530 (Thu, 28 Feb 2019)");
  script_name("Wireshark Security Updates(wnpa-sec-2019-06_wnpa-sec-2019-07_wnpa-sec-2019-08)-Mac OS X");

  script_tag(name:"summary", value:"This host is installed with Wireshark
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - NULL pointer dereferences in epan/dissectors/asn1/tcap/tcap.cnf
    and pan/dissectors/packet-rpcap.c

  - Buffer overflow error in epan/dissectors/packet-ber.c");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to crash Wireshark dissectors by injecting a malformed packet into the network
  or by tricking a victim into opening a malicious packet trace file.");

  script_tag(name:"affected", value:"Wireshark versions 2.4.0 to 2.4.12 and
  2.6.0 to 2.6.6 on Mac OS X");

  script_tag(name:"solution", value:"Upgrade to Wireshark version 2.4.13 or
  2.6.7 or later. Please see the references for more information.");

  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2019-06.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2019-07.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2019-08.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/download.html");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
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

if(version_in_range(version:wirversion, test_version:"2.4.0", test_version2:"2.4.12")){
  fix = "2.4.13";
}

else if(version_in_range(version:wirversion, test_version:"2.6.0", test_version2:"2.6.6")){
  fix = "2.6.7";
}

if(fix)
{
  report = report_fixed_ver(installed_version:wirversion, fixed_version:fix, install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);

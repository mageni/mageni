# Copyright (C) 2023 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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
  script_oid("1.3.6.1.4.1.25623.1.0.124295");
  script_version("2023-03-14T10:10:15+0000");
  script_tag(name:"last_modification", value:"2023-03-14 10:10:15 +0000 (Tue, 14 Mar 2023)");
  script_tag(name:"creation_date", value:"2023-03-10 11:21:47 +0000 (Fri, 10 Mar 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2023-1161");

  script_name("Wireshark Security Update (wnpa-sec-2023-08) - Mac OS X");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_macosx.nasl");
  script_mandatory_keys("Wireshark/MacOSX/Version");

  script_tag(name:"summary", value:"Wireshark is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"This issue occurs when decoding malformed packets from a pcap
  file or from the network, causing an out-of-bounds write, resulting in a Denial of Service and
  limited memory corruption.");

  script_tag(name:"impact", value:"It may be possible to make Wireshark crash by injecting a
  malformed packet onto the wire or by convincing someone to read a malformed packet trace file.");

  script_tag(name:"affected", value:"Wireshark version 3.6.0 through 3.6.11, 4.0 through 4.0.3.");

  script_tag(name:"solution", value:"Update to version 3.6.12, 4.0.4 or later.");

  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2023-08.html");
  script_xref(name:"URL", value:"https://access.redhat.com/security/cve/cve-2023-1161");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_in_range( version: version, test_version: "3.6.0", test_version2: "3.6.11" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.6.12", install_path: location );
  security_message( data: report, port: 0 );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "4.0", test_version2: "4.0.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.0.4", install_path: location );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );

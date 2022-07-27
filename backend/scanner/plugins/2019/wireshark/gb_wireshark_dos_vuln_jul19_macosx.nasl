# Copyright (C) 2019 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113445");
  script_version("2019-07-18T11:38:28+0000");
  script_tag(name:"last_modification", value:"2019-07-18 11:38:28 +0000 (Thu, 18 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-07-18 13:03:54 +0000 (Thu, 18 Jul 2019)");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:N/I:N/A:P");

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-13619");

  script_name("Wireshark 3.0.0 to 3.0.2, 2.6.0 to 2.6.9, and 2.4.0 to 2.4.15 DoS Vulnerability (Mac OS X)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_macosx.nasl");
  script_mandatory_keys("Wireshark/MacOSX/Ver");

  script_tag(name:"summary", value:"Wireshark is prone to a denial of service (DoS) vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"If an attacker injects a malformed packet onto the wire or convinces someone
  to read a malformed packet trace file, the ASN.1 BER and related dissectors could crash.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to crash the Wireshark application.");
  script_tag(name:"affected", value:"Wireshark versions 2.4.0 through 2.4.15, 2.6.0 through 2.6.9
  and 3.0.0 through 3.0.2.");
  script_tag(name:"solution", value:"Update to version 2.4.16, 2.6.10 or 3.0.3 respectively.");

  script_xref(name:"URL", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=15870");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2019-20.html");

  exit(0);
}

CPE = "cpe:/a:wireshark:wireshark";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE ) ) exit( 0 );
version = infos["version"];
location = infos["location"];

if( version_in_range( version: version, test_version: "2.4.0", test_version2: "2.4.15" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.4.16", install_path: location );
  security_message( data: report, port: 0 );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "2.6.0", test_version2: "2.6.9" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.6.10", install_path: location );
  security_message( data: report, port: 0 );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "3.0.0", test_version2: "3.0.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.0.3", install_path: location );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );

# Copyright (C) 2020 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113736");
  script_version("2020-08-03T11:22:52+0000");
  script_tag(name:"last_modification", value:"2020-08-04 10:39:08 +0000 (Tue, 04 Aug 2020)");
  script_tag(name:"creation_date", value:"2020-08-03 11:10:35 +0000 (Mon, 03 Aug 2020)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_cve_id("CVE-2020-15778");

  script_name("OpenSSH <= 8.3p1 Command Injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_openssh_consolidation.nasl");
  script_mandatory_keys("openssh/detected");

  script_tag(name:"summary", value:"OpenSSH is prone to a remote code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"scp of OpenSSH allows command injection in spc.c
  via backtick characters in the destination argument.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker
  to execute arbitrary code on the target machine.");

  script_tag(name:"affected", value:"OpenSSH through version 8.3p1.");

  script_tag(name:"solution", value:"No known solution is available as of 03rd August, 2020.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://github.com/cpandya2909/CVE-2020-15778/");

  exit(0);
}

CPE = "cpe:/a:openbsd:openssh";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less_equal( version: version, test_version: "8.3p1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "None Available", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
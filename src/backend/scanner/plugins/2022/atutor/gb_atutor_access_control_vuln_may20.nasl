# Copyright (C) 2022 Greenbone Networks GmbH
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

CPE = "cpe:/a:atutor:atutor";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127214");
  script_version("2022-10-12T10:13:47+0000");
  script_tag(name:"last_modification", value:"2022-10-12 10:13:47 +0000 (Wed, 12 Oct 2022)");
  script_tag(name:"creation_date", value:"2022-10-06 11:49:35 +0000 (Thu, 06 Oct 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-15 18:15:00 +0000 (Fri, 15 Apr 2022)");

  script_cve_id("CVE-2021-43498");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("ATutor <= 2.2.4 Access Control Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_atutor_detect.nasl");
  script_mandatory_keys("atutor/detected");

  script_tag(name:"summary", value:"Atutor is prone to an access control vulnerability");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the
  target host.");

  script_tag(name:"insight", value:"Weak password reset hash in password_reminder.php lead to
  access control vulnerability.");

  script_tag(name:"affected", value:"Atutor version 2.2.4 and prior.");

  script_tag(name:"solution", value:"No known solution is available as of 10th October, 2022.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/157563/ATutor-LMS-2.2.4-Weak-Password-Reset-Hash.html");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if ( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if ( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if ( version_is_less_equal( version: version, test_version: "2.2.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "None", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 0 );

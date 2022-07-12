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
  script_oid("1.3.6.1.4.1.25623.1.0.112785");
  script_version("2020-07-22T09:33:45+0000");
  script_tag(name:"last_modification", value:"2020-07-23 09:54:39 +0000 (Thu, 23 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-07-22 09:31:00 +0000 (Wed, 22 Jul 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-3481");

  script_name("ClamAV 0.102.0 < 0.102.4 DoS Vulnerability (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_clamav_remote_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("ClamAV/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"ClamAV is prone to a denial-of-service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Improper error handling could cause a crash due to a NULL pointer dereference.");

  script_tag(name:"impact", value:"Successful exploitation would cause a denial-of-service condition.");

  script_tag(name:"affected", value:"ClamAV versions 0.102.0 through 0.102.3.");

  script_tag(name:"solution", value:"Update to version 0.102.4 or later.");

  script_xref(name:"URL", value:"https://blog.clamav.net/2020/07/clamav-01024-security-patch-released.html");

  exit(0);
}

CPE = "cpe:/a:clamav:clamav";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_in_range( version: vers, test_version: "0.102.0", test_version2: "0.102.3" ) ) {
  report = report_fixed_ver( installed_version: vers, fixed_version: "0.102.4", install_path: path );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );

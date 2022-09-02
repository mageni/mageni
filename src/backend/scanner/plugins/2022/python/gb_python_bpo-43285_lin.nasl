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

CPE = "cpe:/a:python:python";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126132");
  script_version("2022-09-01T08:42:45+0000");
  script_tag(name:"last_modification", value:"2022-09-01 10:46:45 +0000 (Thu, 01 Sep 2022)");
  script_tag(name:"creation_date", value:"2022-09-01 08:03:11 +0200 (Thu, 01 Sep 2022)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2021-4189");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Python < 3.6.14, 3.7.x < 3.7.11, 3.8.x < 3.8.9, 3.9.x < 3.9.3 (bpo-43285) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_python_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("python/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Python is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"This flaw allows an attacker to set up a malicious FTP server,
  that can trick FTP clients into connecting back to a given IP address and port.");

  script_tag(name:"affected", value:"Python prior to version 3.6.14, versions 3.7.x prior to 3.7.11,
  3.8.x prior to 3.8.9 and 3.9.x prior to 3.9.3.");

  script_tag(name:"solution", value:"Update to version 3.6.14, 3.7.11, 3.8.9, 3.9.3 or later.");

  script_xref(name:"URL", value:"https://python-security.readthedocs.io/vuln/ftplib-pasv.html");
  script_xref(name:"Advisory-ID", value:"bpo-43285");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version:version, test_version:"3.6.14" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.6.14", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "3.7.0", test_version_up: "3.7.11" )) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.7.11", install_path: location );
  security_message(port: port, data: report);
  exit(0);
}


if( version_in_range_exclusive( version: version, test_version_lo: "3.8.0", test_version_up: "3.8.9" )) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.8.9", install_path: location );
  security_message(port: port, data: report);
  exit(0);
}

if( version_in_range_exclusive( version: version, test_version_lo: "3.9.0", test_version_up: "3.9.3" )) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.9.3", install_path: location );
  security_message(port: port, data: report);
  exit(0);
}

exit( 99 );

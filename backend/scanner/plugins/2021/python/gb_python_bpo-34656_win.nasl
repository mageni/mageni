# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.118240");
  script_version("2021-10-06T08:01:36+0000");
  script_tag(name:"last_modification", value:"2021-10-06 10:22:49 +0000 (Wed, 06 Oct 2021)");
  script_tag(name:"creation_date", value:"2021-10-04 12:04:36 +0200 (Mon, 04 Oct 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-29 15:15:00 +0000 (Thu, 29 Oct 2020)");

  script_cve_id("CVE-2018-20406");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Python 3.4.x < 3.4.10, 3.5.x < 3.5.7, 3.6.x < 3.6.7, 3.7.x < 3.7.1 Python Issue (bpo-34656) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_python_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("python/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Python is prone to a denial of service (DoS) vulnerability in the
  'pickle.load()' function.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"'Modules/_pickle.c' has an integer overflow via a large
  'LONG_BINPUT' value that is mishandled during a 'resize to twice the size' attempt.");

  script_tag(name:"impact", value:"This issue might cause memory exhaustion, but is only relevant
  if the pickle format is used for serializing tens or hundreds of gigabytes of data.");

  script_tag(name:"affected", value:"Python version 3.4.0 through 3.4.9, 3.5.0 through 3.5.6, 3.6.0
  through 3.6.6 and 3.7.x before 3.7.1.");

  script_tag(name:"solution", value:"Update to version 3.4.10, 3.5.7, 3.6.7, 3.7.1 or later.");

  script_xref(name:"URL", value:"https://python-security.readthedocs.io/vuln/pickle-load-dos.html");
  script_xref(name:"Advisory-ID", value:"bpo-34656");

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

if( version_in_range( version:version, test_version:"3.4", test_version2:"3.4.9" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.4.10", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range( version:version, test_version:"3.5", test_version2:"3.5.6" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.5.7", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range( version:version, test_version:"3.6", test_version2:"3.6.6" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.6.7", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}
if( version_is_greater_equal( version:version, test_version:"3.7.0" ) &&
    version_is_less( version:version, test_version:"3.7.1" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.7.1", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

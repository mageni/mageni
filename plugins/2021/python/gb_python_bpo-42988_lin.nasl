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
  script_oid("1.3.6.1.4.1.25623.1.0.118175");
  script_version("2021-09-21T14:01:15+0000");
  script_tag(name:"last_modification", value:"2021-09-22 10:15:34 +0000 (Wed, 22 Sep 2021)");
  script_tag(name:"creation_date", value:"2021-09-01 09:55:13 +0200 (Wed, 01 Sep 2021)");
  script_tag(name:"cvss_base", value:"2.7");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-29 10:15:00 +0000 (Tue, 29 Jun 2021)");

  script_cve_id("CVE-2021-3426");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Python < 3.6.14, 3.7.x < 3.7.11, 3.8.x < 3.8.9, 3.9.x < 3.9.3 Python Issue (bpo-42988) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_python_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("python/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Python is prone to an information disclosure vulnerability via
  pydoc getfile.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Running 'pydoc -p' allows other local users to extract arbitrary
  files.

  The '/getfile?key=path' URL allows to read arbitrary file on the filesystem.");

  script_tag(name:"impact", value:"A local or adjacent attacker who discovers or is able to convince
  another local or adjacent user to start a pydoc server could access the server and use it to disclose
  sensitive information belonging to the other user that they would not normally be able to access.");

  script_tag(name:"affected", value:"Python prior to version 3.6.14, versions 3.7.x prior to 3.7.11,
  3.8.x prior to 3.8.9 and 3.9.x prior to 3.9.3.");

  script_tag(name:"solution", value:"Update to version 3.6.14, 3.7.11, 3.8.9, 3.9.3 or later.");

  script_xref(name:"URL", value:"https://python-security.readthedocs.io/vuln/pydoc-getfile.html");
  script_xref(name:"Advisory-ID", value:"bpo-42988");

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

if( version_in_range( version:version, test_version:"3.7.0", test_version2:"3.7.10" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.7.11", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range( version:version, test_version:"3.8.0", test_version2:"3.8.8" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.8.9", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range( version:version, test_version:"3.9.0", test_version2:"3.9.2" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.9.3", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

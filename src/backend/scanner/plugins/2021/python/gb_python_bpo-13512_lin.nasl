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
  script_oid("1.3.6.1.4.1.25623.1.0.118266");
  script_version("2021-11-03T03:03:35+0000");
  script_tag(name:"last_modification", value:"2021-11-03 03:03:35 +0000 (Wed, 03 Nov 2021)");
  script_tag(name:"creation_date", value:"2021-11-01 11:45:13 +0100 (Mon, 01 Nov 2021)");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2011-4944");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Python < 2.7.4, 3.2.x < 3.2.4, 3.3.x < 3.3.1 pypirc created insecurely (bpo-13512) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_python_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("python/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Python is prone to an access control vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Python creates '~/.pypirc' with world-readable permissions
  before changing them after data has been written, which introduces a race condition that
  allows local users to obtain a username and password by reading this file.");

  script_tag(name:"affected", value:"Python prior to version 2.7.4, versions 3.2.x prior to 3.2.4
  and 3.3.x prior to 3.3.1.");

  script_tag(name:"solution", value:"Update to version 2.7.4, 3.2.4, 3.3.1 or later.");

  script_xref(name:"URL", value:"https://python-security.readthedocs.io/vuln/pypirc-created-insecurely.html");
  script_xref(name:"Advisory-ID", value:"bpo-13512");

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

if( version_is_less( version:version, test_version:"2.7.4" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"2.7.4", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range( version:version, test_version:"3.2.0", test_version2:"3.2.3" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.2.4", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_is_greater_equal( version:version, test_version:"3.3.0" ) &&
    version_is_less( version:version, test_version:"3.3.1" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.3.1", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

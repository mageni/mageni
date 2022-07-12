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
  script_oid("1.3.6.1.4.1.25623.1.0.118191");
  script_version("2021-09-21T14:01:15+0000");
  script_tag(name:"last_modification", value:"2021-09-22 10:15:34 +0000 (Wed, 22 Sep 2021)");
  script_tag(name:"creation_date", value:"2021-09-11 10:50:32 +0200 (Sat, 11 Sep 2021)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-26 21:26:00 +0000 (Fri, 26 Mar 2021)");

  script_cve_id("CVE-2020-15523");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Python < 3.5.10, 3.6.x < 3.6.12, 3.7.x < 3.7.9, 3.8.x - 3.8.4rc1, 3.9.x - 3.9.0b4 Python Issue (bpo-29778) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_python_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("python/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Python is prone to  an invalid search path vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"When the runtime attempts to pre-load 'python3.dll', an invalid
  search path occurs during Py_Initialize(). If Py_SetPath() has been called, the expected location
  is not set, and locations elsewhere on the user's system will be searched.

  This issue is not triggered when running 'python.exe'. It only applies when 'CPython' has been
  embedded in another application.");

  script_tag(name:"affected", value:"Python prior to version 3.5.10, 3.6.x prior to version 3.6.12,
  versions 3.7.x prior to 3.7.9, 3.8.x through 3.8.4rc1 and 3.9.x through 3.9.0b4.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for
  more information.");

  script_xref(name:"URL", value:"https://python-security.readthedocs.io/vuln/pysetpath-python-dll-path.html");
  script_xref(name:"Advisory-ID", value:"bpo-29778");

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

if( version_is_less( version:version, test_version:"3.5.10" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.5.10", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range( version:version, test_version:"3.6.0", test_version2:"3.6.11" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.6.12", install_path:location);
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range( version:version, test_version:"3.7.0", test_version2:"3.7.8" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.7.9", install_path:location);
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range( version:version, test_version:"3.8.0", test_version2:"3.8.4rc1" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"See reference", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range( version:version, test_version:"3.9.0", test_version2:"3.9.0b4" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"See reference", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

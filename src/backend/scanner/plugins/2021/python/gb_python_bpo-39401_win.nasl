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
  script_oid("1.3.6.1.4.1.25623.1.0.118195");
  script_version("2021-09-21T14:01:15+0000");
  script_tag(name:"last_modification", value:"2021-09-22 10:15:34 +0000 (Wed, 22 Sep 2021)");
  script_tag(name:"creation_date", value:"2021-09-11 10:50:32 +0200 (Sat, 11 Sep 2021)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-01 17:13:00 +0000 (Sat, 01 Feb 2020)");

  script_cve_id("CVE-2020-8315");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Python 3.6.x < 3.6.11, 3.7.x < 3.7.7, 3.8.x < 3.8.2 Python Issue (bpo-39401) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_python_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("python/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Python (CPython) on Windows 7 is prone to an uncontrolled search
  path vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"In Python (CPython) an insecure dependency load upon launch on
  Windows 7 may result in an attacker's copy of api-ms-win-core-path-l1-1-0.dll being loaded and
  used instead of the system's copy.

  Note: Windows 8 and later are unaffected.");

  script_tag(name:"affected", value:"Python versions 3.6.x prior to version 3.6.11, versions 3.7.x
  prior to 3.7.7, 3.8.x prior to 3.8.2.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for
  more information.");

  script_xref(name:"URL", value:"https://python-security.readthedocs.io/vuln/unsafe-dll-load-windows-7.html");
  script_xref(name:"Advisory-ID", value:"bpo-39401");

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

if( version_in_range( version:version, test_version:"3.6", test_version2:"3.6.10" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.6.11", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range( version:version, test_version:"3.7.0", test_version2:"3.7.6" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.7.7", install_path:location);
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range( version:version, test_version:"3.8.0", test_version2:"3.8.1" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.8.2", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

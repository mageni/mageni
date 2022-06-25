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
  script_oid("1.3.6.1.4.1.25623.1.0.118206");
  script_version("2021-10-07T11:01:20+0000");
  script_tag(name:"last_modification", value:"2021-10-07 11:23:18 +0000 (Thu, 07 Oct 2021)");
  script_tag(name:"creation_date", value:"2021-09-12 10:50:32 +0200 (Sun, 12 Sep 2021)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_cve_id("CVE-2019-9948");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Python 2.x < 2.7.17, 3.5.x < 3.5.8, 3.6.x < 3.6.9, 3.7.x < 3.7.4 Protection Bypass Vulnerability (bpo-35907) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_python_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("python/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Python is prone to a protection bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"urllib supports the 'local_file:' scheme, which makes it easier
  for remote attackers to bypass protection mechanisms that blacklist 'file:' URIs, as demonstrated
  by triggering a 'urllib.urlopen('local_file:///etc/passwd')' call.");

  script_tag(name:"affected", value:"Python 2.x prior to version 2.7.17, versions 3.5.x prior to 3.5.8,
  3.6.x prior to 3.6.9 and 3.7.x prior to 3.7.4.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for
  more information.");

  script_xref(name:"URL", value:"https://python-security.readthedocs.io/vuln/urllib-local-file-scheme.html");
  script_xref(name:"Advisory-ID", value:"bpo-35907");

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

if( version_in_range( version:version, test_version:"2.0", test_version2:"2.7.16" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"2.7.17", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range( version:version, test_version:"3.5.0", test_version2:"3.5.7" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.5.8", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range( version:version, test_version:"3.6.0", test_version2:"3.6.8" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.6.9", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range( version:version, test_version:"3.7.0", test_version2:"3.7.3" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.7.4", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

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
  script_oid("1.3.6.1.4.1.25623.1.0.118217");
  script_version("2021-10-06T08:01:36+0000");
  script_tag(name:"last_modification", value:"2021-10-06 10:22:49 +0000 (Wed, 06 Oct 2021)");
  script_tag(name:"creation_date", value:"2021-09-12 10:50:32 +0200 (Sun, 12 Sep 2021)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-29 13:25:00 +0000 (Thu, 29 Mar 2018)");

  script_cve_id("CVE-2018-1000117");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Python < 3.4.9, 3.5.x < 3.5.6, 3.6.x < 3.6.5 Python Issue (bpo-33001) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_python_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("python/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Python is prone to a buffer overflow vulnerability in
  'os.symlink'.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A buffer overflow vulnerability in os.symlink() function can
  result in arbitrary code execution, likely escalation of privilege. This attack appears to be
  exploitable via a python script that creates a symlink with an attacker controlled name or
  location.");

  script_tag(name:"affected", value:"Python prior to version 3.4.9, versions 3.5.x prior to 3.5.6,
  and 3.6.x prior to 3.6.5.");

  script_tag(name:"solution", value:"Update to version 3.4.9, 3.5.6, 3.6.5 or later.");

  script_xref(name:"URL", value:"https://python-security.readthedocs.io/vuln/buffer-overflow-os-symlink-windows.html");
  script_xref(name:"Advisory-ID", value:"bpo-33001");

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

if( version_is_less( version:version, test_version:"3.4.9" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.4.9", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range( version:version, test_version:"3.5.0", test_version2:"3.5.5" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.5.6", install_path:location);
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range( version:version, test_version:"3.6.0", test_version2:"3.6.4" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.6.5", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

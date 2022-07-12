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
  script_oid("1.3.6.1.4.1.25623.1.0.118187");
  script_version("2021-09-21T14:01:15+0000");
  script_tag(name:"last_modification", value:"2021-09-22 10:15:34 +0000 (Wed, 22 Sep 2021)");
  script_tag(name:"creation_date", value:"2021-09-11 10:50:32 +0200 (Sat, 11 Sep 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-29 15:15:00 +0000 (Tue, 29 Jun 2021)");

  script_cve_id("CVE-2020-27619");

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Python < 3.6.13, 3.7.x < 3.7.10, 3.8.x < 3.8.7, 3.9.x < 3.9.1 Python Issue (bpo-41944) - Mac OS X");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_python_consolidation.nasl");
  script_mandatory_keys("python/mac-os-x/detected");

  script_tag(name:"summary", value:"Python is prone to a remote code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"By default, the tests are not run with network resources enabled
  and so the Python test suite is safe. But if the Python test suite is run explicitly with the
  'network' resource enabled (-u network or -u all command line option), the CJK codecs tests of the
  Python test suite run eval() on content received via HTTP from pythontest.net.");

  script_tag(name:"impact", value:"If an attacker can compromise the pythontest.net server, they gain
  arbitrary code execution on all buildbots.

  If an attacker has control over the network connection of a machine running the Python test suite,
  they gain arbitrary code execution there.");

  script_tag(name:"affected", value:"Python prior to version 3.6.13, versions 3.7.x prior to 3.7.10,
  3.8.x prior to 3.8.7 and 3.9.x prior to 3.9.1.");

  script_tag(name:"solution", value:"Update to version 3.6.13, 3.7.10, 3.8.7, 3.9.1 or later.");

  script_xref(name:"URL", value:"https://python-security.readthedocs.io/vuln/cjk-codec-download-eval.html");
  script_xref(name:"Advisory-ID", value:"bpo-41944");

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

if( version_is_less( version:version, test_version:"3.6.13" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.6.13", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range( version:version, test_version:"3.7.0", test_version2:"3.7.9" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.7.10", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range( version:version, test_version:"3.8.0", test_version2:"3.8.6" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.8.7", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_is_equal( version:version, test_version:"3.9.0" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.9.1", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

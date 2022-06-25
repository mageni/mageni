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
  script_oid("1.3.6.1.4.1.25623.1.0.118216");
  script_version("2021-10-07T11:01:20+0000");
  script_tag(name:"last_modification", value:"2021-10-07 11:23:18 +0000 (Thu, 07 Oct 2021)");
  script_tag(name:"creation_date", value:"2021-09-12 10:50:32 +0200 (Sun, 12 Sep 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_cve_id("CVE-2019-16056");

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Python < 2.7.17, 3.x < 3.5.8, 3.6.x < 3.6.10, 3.7.x < 3.7.5 Improper Input Validation Vulnerability (bpo-34155) - Mac OS X");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_python_consolidation.nasl");
  script_mandatory_keys("python/mac-os-x/detected");

  script_tag(name:"summary", value:"The email module in Python is vulnerable due to improper
  input validation.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The email module wrongly parses email addresses that contain
  multiple '@' characters. An application that uses the email module and implements some kind of
  checks on the 'From/To' headers of a message could be tricked into accepting an email address
  that should be denied.");

  script_tag(name:"affected", value:"Python prior to version 2.7.17, versions 3.x prior to 3.5.8,
  3.6.x prior to 3.6.10 and 3.7.x prior to 3.7.5.");

  script_tag(name:"solution", value:"Update to version 2.7.17, 3.5.8, 3.6.10, 3.7.5 or later.");

  script_xref(name:"URL", value:"https://python-security.readthedocs.io/vuln/email-parseaddr-domain.html");
  script_xref(name:"Advisory-ID", value:"bpo-34155");

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

if( version_is_less( version:version, test_version:"2.7.17" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"2.7.17", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range( version:version, test_version:"3.0", test_version2:"3.5.7" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.5.8", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range( version:version, test_version:"3.6.0", test_version2:"3.6.9" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.6.10", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range( version:version, test_version:"3.7.0", test_version2:"3.7.4" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.7.5", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

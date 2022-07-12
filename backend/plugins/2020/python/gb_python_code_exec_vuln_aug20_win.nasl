# Copyright (C) 2020 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113738");
  script_version("2020-08-06T07:34:29+0000");
  script_tag(name:"last_modification", value:"2020-08-06 10:12:02 +0000 (Thu, 06 Aug 2020)");
  script_tag(name:"creation_date", value:"2020-08-06 07:09:45 +0000 (Thu, 06 Aug 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-15801");

  script_name("Python <= 3.8.4 Arbitrary Code Execution Vulnerability (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_python_detect_win.nasl");
  script_mandatory_keys("python/win/detected");

  script_tag(name:"summary", value:"Python is prone to an arbitrary code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability exists because
  sys.path restrictions specified in a python38._pth file are ignored,
  allowing code to be loaded from arbitrary locations.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker
  to execute arbitrary code on the target machine.");

  script_tag(name:"affected", value:"Python through version 3.8.4.");

  script_tag(name:"solution", value:"Update to version 3.8.5 or later.");

  script_xref(name:"URL", value:"https://bugs.python.org/issue41304");
  script_xref(name:"URL", value:"https://github.com/python/cpython/pull/21495");

  exit(0);
}

CPE = "cpe:/a:python:python";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "3.8.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.8.5", install_path: location );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );

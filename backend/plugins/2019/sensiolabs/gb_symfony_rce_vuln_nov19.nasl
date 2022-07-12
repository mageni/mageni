# Copyright (C) 2019 Greenbone Networks GmbH, https://www.greenbone.net
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.112671");
  script_version("2019-11-22T10:58:15+0000");
  script_tag(name:"last_modification", value:"2019-11-22 10:58:15 +0000 (Fri, 22 Nov 2019)");
  script_tag(name:"creation_date", value:"2019-11-22 10:38:11 +0000 (Fri, 22 Nov 2019)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-18889");

  script_name("Symfony 3.4.0 <= 3.4.34, 4.2.0 <= 4.2.11 and 4.3.0 <= 4.3.7 Remote Code Execution Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_symfony_consolidation.nasl");
  script_mandatory_keys("symfony/detected");

  script_tag(name:"summary", value:"Symfony is prone to a remote code execution.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"When an instance of TagAwareAdapter is destructed,
  Symfony execute callables stored in privates properties in order to invalidates tags.
  When the instance has been created by unserializing an external payload, those properties
  are not checked leading to a remote code execution.");

  script_tag(name:"affected", value:"Symfony 3.4.0 to 3.4.34, 4.2.0 to 4.2.11 and 4.3.0 to 4.3.7.");

  script_tag(name:"solution", value:"The issue has been fixed in Symfony 3.4.35, 4.2.12 and 4.3.8.

  NOTE: No fixes are provided for Symfony 3.1, 3.2, 3.3, 4.0 and 4.1 as they are not maintained anymore.");

  script_xref(name:"URL", value:"https://symfony.com/blog/cve-2019-18889-forbid-serializing-abstractadapter-and-tagawareadapter-instances");

  exit(0);
}

CPE = "cpe:/a:sensiolabs:symfony";

include( "host_details.inc" );
include( "version_func.inc" );

if( isnull( port = get_app_port( cpe: CPE ) ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE) ) exit( 0 );
version = infos["version"];
location = infos["location"];

if( version_in_range( version: version, test_version: "3.4.0", test_version2: "3.4.34" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.4.35", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "4.2.0", test_version2: "4.2.11" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.2.12", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "4.3.0", test_version2: "4.3.7" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.3.8", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );

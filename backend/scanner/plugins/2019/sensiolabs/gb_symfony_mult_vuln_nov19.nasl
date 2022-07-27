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
  script_oid("1.3.6.1.4.1.25623.1.0.112669");
  script_version("2019-11-22T10:58:15+0000");
  script_tag(name:"last_modification", value:"2019-11-22 10:58:15 +0000 (Fri, 22 Nov 2019)");
  script_tag(name:"creation_date", value:"2019-11-22 10:38:11 +0000 (Fri, 22 Nov 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-11325", "CVE-2019-18886");

  script_name("Symfony 4.2.x < 4.2.12, 4.3.x < 4.3.8 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_symfony_consolidation.nasl");
  script_mandatory_keys("symfony/detected");

  script_tag(name:"summary", value:"Symfony is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - The ability to enumerate users was possible without relevant permissions
  due to different handling depending on whether the user existed or not when
  attempting to use the switch users functionality.

  - Some strings were not properly escaped when being dumped by the VarExporter
  component. The VarExporter is notably used by the Symfony Cache Component
  PhpFilesAdapter and PhpArrayAdapter adapters.");

  script_tag(name:"affected", value:"Symfony versions 4.2.0 to 4.2.11 and 4.3.0 to 4.3.7.");

  script_tag(name:"solution", value:"The issue has been fixed in Symfony 4.2.12 and 4.3.8.

  NOTE: No fixes are provided for Symfony 4.1 as they are not maintained anymore.
  It is recommended to upgrade to a supported version as soon as possible.");

  script_xref(name:"URL", value:"https://symfony.com/blog/cve-2019-11325-fix-escaping-of-strings-in-varexporter");
  script_xref(name:"URL", value:"https://symfony.com/blog/cve-2019-18886-prevent-user-enumeration-using-switch-user-functionality");

  exit(0);
}

CPE = "cpe:/a:sensiolabs:symfony";

include( "host_details.inc" );
include( "version_func.inc" );

if( isnull( port = get_app_port( cpe: CPE ) ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE) ) exit( 0 );
version = infos["version"];
location = infos["location"];

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

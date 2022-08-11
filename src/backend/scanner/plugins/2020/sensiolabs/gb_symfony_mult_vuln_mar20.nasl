# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.112719");
  script_version("2020-04-01T09:01:06+0000");
  script_tag(name:"last_modification", value:"2020-04-02 09:54:57 +0000 (Thu, 02 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-04-01 09:28:11 +0000 (Wed, 01 Apr 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-5255", "CVE-2020-5275");

  script_name("Symfony 4.4.x < 4.4.7, 5.0.x < 5.0.7 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_symfony_consolidation.nasl");
  script_mandatory_keys("symfony/detected");

  script_tag(name:"summary", value:"Symfony is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - When a Response does not contain a Content-Type header, Symfony falls back to the format defined
  in the Accept header of the request, leading to a possible mismatch between the response's content
  and Content-Type header. When the response is cached, this can lead to a corrupted cache where the
  cached format is not the right one (CVE-2020-5255)

  - When a Firewall checks an access control rule (using the unanimous strategy), it iterates over
  all rule attributes and grant access only if all calls to the accessDecisionManager decide to grant access.

  A bug was introduced that prevents the check of attributes as soon as
  accessDecisionManager decide to grant access on one attribute (CVE-2020-5275)");

  script_tag(name:"affected", value:"Symfony versions 4.4.0 to 4.4.6 and 5.0.0 to 5.0.6.");

  script_tag(name:"solution", value:"The issues have been fixed in Symfony 4.4.7 and 5.0.7.");

  script_xref(name:"URL", value:"https://github.com/symfony/symfony/security/advisories/GHSA-mcx4-f5f5-4859");
  script_xref(name:"URL", value:"https://github.com/symfony/symfony/security/advisories/GHSA-g4m9-5hpf-hx72");

  exit(0);
}

CPE = "cpe:/a:sensiolabs:symfony";

include( "host_details.inc" );
include( "version_func.inc" );

if( isnull( port = get_app_port( cpe: CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_in_range( version: version, test_version: "4.4.0", test_version2: "4.4.6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.4.7", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "5.0.0", test_version2: "5.0.6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.0.7", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );

# Copyright (C) 2022 Greenbone Networks GmbH
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

CPE = "cpe:/a:instawp:string-locator";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170186");
  script_version("2022-10-11T10:12:36+0000");
  script_tag(name:"last_modification", value:"2022-10-11 10:12:36 +0000 (Tue, 11 Oct 2022)");
  script_tag(name:"creation_date", value:"2022-10-04 14:04:48 +0000 (Tue, 04 Oct 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2022-2434");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress String Locator Plugin <= 2.5.0 Deserialization of Untrusted Data Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/string-locator/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'String Locator' is prone to a
  deserialization of untrusted data vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The String Locator plugin for WordPress is vulnerable to
  deserialization of untrusted input via the 'string-locator-path' parameter. This makes it possible
  for unauthenticated users to call files using a PHAR wrapper, granted they can trick a site
  administrator into performing an action such as clicking on a link (CSRF), that will deserialize and
  call arbitrary PHP Objects that can be used to perform a variety of malicious actions granted a POP
  chain is also present. It also requires that the attacker is successful in uploading a file with the
  serialized payload.");

  script_tag(name:"affected", value:"WordPress String Locator plugin prior to version 2.5.1.");

  script_tag(name:"solution", value:"Update to version 2.5.1 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/vulnerability-advisories/#CVE-2022-2434");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if ( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if ( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if ( version_is_less( version:version, test_version:"2.5.1" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"2.5.1", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

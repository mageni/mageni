# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.113539");
  script_version("2019-10-07T09:58:47+0000");
  script_tag(name:"last_modification", value:"2019-10-07 09:58:47 +0000 (Mon, 07 Oct 2019)");
  script_tag(name:"creation_date", value:"2019-10-07 11:42:39 +0000 (Mon, 07 Oct 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-15032", "CVE-2019-15033");

  script_name("Pydio <= 6.0.8 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_pydio_detect.nasl");
  script_mandatory_keys("pydio/installed");

  script_tag(name:"summary", value:"Pydio is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Following vulnerabilities exist:

  - Due to mishandling error reporting when a directory allows unauthenticated uploads,
    an attacker can obtain sensitive internal server information.

  - Pydio allows authenticated SSRF during a Remote Link Feature download.
    An attacker can specify an intranet address in the file parameter to index.php
    when sending a file to a remote server.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to obtain
  sensitive information from the affected server or other servers
  in the same network.");
  script_tag(name:"affected", value:"Pydio through version 6.0.8.");
  script_tag(name:"solution", value:"Update to version 7.0.0 or later.");

  script_xref(name:"URL", value:"https://heitorgouvea.me/2019/09/17/CVE-2019-15032");
  script_xref(name:"URL", value:"https://heitorgouvea.me/2019/09/17/CVE-2019-15033");

  exit(0);
}

CPE = "cpe:/a:pydio:pydio";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );
version = infos["version"];
location = infos["location"];

if( version_is_less_equal( version: version, test_version: "6.0.8" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "7.0.0", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
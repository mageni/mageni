# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.112712");
  script_version("2020-03-18T12:51:35+0000");
  script_tag(name:"last_modification", value:"2020-03-18 13:55:00 +0000 (Wed, 18 Mar 2020)");
  script_tag(name:"creation_date", value:"2020-03-18 12:44:11 +0000 (Wed, 18 Mar 2020)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-20452", "CVE-2019-20453");

  script_name("Pydio < 8.2.4 Multiple PHP Object Injection Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_pydio_detect.nasl");
  script_mandatory_keys("pydio/installed");

  script_tag(name:"summary", value:"Pydio is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - A PHP object injection is present in the page plugins/core.access/src/RecycleBinManager.php (CVE-2019-20452)

  - A PHP object injection is present in the page plugins/uploader.http/HttpDownload.php (CVE-2019-20453)");
  script_tag(name:"impact", value:"An authenticated user with basic privileges can inject objects and achieve remote code execution.");
  script_tag(name:"affected", value:"Pydio before version 8.2.4.");
  script_tag(name:"solution", value:"Update to version 8.2.4 or later.");

  script_xref(name:"URL", value:"https://pydio.com/en/community/releases/pydio-core/pydio-core-pydio-enterprise-824-security-release");
  script_xref(name:"URL", value:"https://www.certilience.fr/2020/03/cve-2019-20452-vulnerabilite-php-object-injection-pydio-core/");
  script_xref(name:"URL", value:"https://www.certilience.fr/2020/03/cve-2019-20453-vulnerabilite-php-object-injection-pydio-core/");

  exit(0);
}

CPE = "cpe:/a:pydio:pydio";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less_equal( version: version, test_version: "8.2.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "8.2.4", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );

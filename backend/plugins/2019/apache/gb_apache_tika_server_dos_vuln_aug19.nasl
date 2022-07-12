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
  script_oid("1.3.6.1.4.1.25623.1.0.112619");
  script_version("2019-08-05T13:49:59+0000");
  script_tag(name:"last_modification", value:"2019-08-05 13:49:59 +0000 (Mon, 05 Aug 2019)");
  script_tag(name:"creation_date", value:"2019-08-05 13:28:12 +0000 (Mon, 05 Aug 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-10093");

  script_name("Apache Tika Server 1.19 < 1.22 Denial of Service Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_apache_tika_server_detect.nasl");
  script_mandatory_keys("Apache/Tika/Server/Installed");

  script_tag(name:"summary", value:"Apache Tika Server is prone to a denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A carefully crafted 2003ml or 2006ml file could consume all available
  SAXParsers in the pool and lead to very long hangs.");

  script_tag(name:"affected", value:"Apache Tika versions 1.19 through 1.21.");

  script_tag(name:"solution", value:"Update to version 1.22 or later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread.html/a5a44eff1b9eda3bc69d22943a1030c43d376380c75d3ab04d0c1a21@%3Cdev.tika.apache.org%3E");

  exit(0);
}

CPE = "cpe:/a:apache:tika";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
path = infos["location"];

if( version_in_range( version: version, test_version: "1.19", test_version2: "1.21" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.22", install_path: path );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );

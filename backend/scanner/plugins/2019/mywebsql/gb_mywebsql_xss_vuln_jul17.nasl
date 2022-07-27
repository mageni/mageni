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
  script_oid("1.3.6.1.4.1.25623.1.0.113335");
  script_version("$Revision: 13635 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-13 13:07:58 +0100 (Wed, 13 Feb 2019) $");
  script_tag(name:"creation_date", value:"2019-02-13 11:26:40 +0200 (Wed, 13 Feb 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2017-1000011");

  script_name("MyWebSQL <= 3.6 Cross-Site Scripting (XSS) Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_mywebsql_http_detect.nasl");
  script_mandatory_keys("mywebsql/detected");

  script_tag(name:"summary", value:"MyWebSQL is prone to a Cross-Site Scripting (XSS) Vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The vulnerability exists within the database manager component.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to inject
  arbitrary JavaScript or HTML into the site.");
  script_tag(name:"affected", value:"MyWebSQL through version 3.6.");
  script_tag(name:"solution", value:"Update to version 3.7.");

  script_xref(name:"URL", value:"https://github.com/Samnan/MyWebSQL");

  exit(0);
}

CPE = "cpe:/a:mywebsql:mywebsql";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_is_less_equal( version: version, test_version: "3.6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.7" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );

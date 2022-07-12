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
  script_oid("1.3.6.1.4.1.25623.1.0.113644");
  script_version("2020-03-11T12:22:13+0000");
  script_tag(name:"last_modification", value:"2020-03-12 11:06:29 +0000 (Thu, 12 Mar 2020)");
  script_tag(name:"creation_date", value:"2020-02-21 09:31:31 +0000 (Fri, 21 Feb 2020)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-20107", "CVE-2020-8841");

  script_name("TestLink <= 1.9.19 Multiple SQL Injection Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("testlink_detect.nasl");
  script_mandatory_keys("testlink/detected");

  script_tag(name:"summary", value:"TestLink is prone to multiple SQL injection vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"TestLink is prone to multiple authenticated SQL injection vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation would allow an authenticated attacker to
  read or modify sensitive information or even execute arbitrary commands on the target system.");

  script_tag(name:"affected", value:"TestLink version 1.9.19 and prior.");

  script_tag(name:"solution", value:"Update to version 1.9.20 or later.");

  script_xref(name:"URL", value:"https://github.com/ver007/testlink-1.9.19-sqlinject");
  script_xref(name:"URL", value:"http://mantis.testlink.org/view.php?id=8829");

  exit(0);
}

CPE = "cpe:/a:testlink:testlink";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "1.9.20" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.9.20", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );

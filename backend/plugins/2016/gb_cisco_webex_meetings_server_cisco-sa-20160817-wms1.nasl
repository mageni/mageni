# Copyright (C) 2016 Greenbone Networks GmbH
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

CPE = "cpe:/a:cisco:webex_meetings_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106192");
  script_version("2020-12-21T11:11:24+0000");
  script_cve_id("CVE-2016-1484");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-12-21 15:00:31 +0000 (Mon, 21 Dec 2020)");
  script_tag(name:"creation_date", value:"2016-08-19 12:02:46 +0700 (Fri, 19 Aug 2016)");
  script_name("Cisco WebEx Meetings Server Information Disclosure Vulnerability (cisco-sa-20160817-wms1)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_webex_meetings_server_detect.nasl");
  script_mandatory_keys("cisco/webex/meetings_server/detected");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160817-wms1");

  script_tag(name:"summary", value:"Cisco WebEx Meetings Server is prone to an information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to lack of proper authentication controls.");

  script_tag(name:"impact", value:"An attacker could exploit this vulnerability to learn sensitive
  information about the application.");

  script_tag(name:"affected", value:"Cisco WebEx Meetings Server 2.6.");

  script_tag(name:"solution", value:"Update to Cisco WebEx Meetings Server 2.7.1.12 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( vers == "2.6" ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.7.1.12", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

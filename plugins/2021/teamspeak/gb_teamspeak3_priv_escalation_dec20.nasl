# Copyright (C) 2021 Greenbone Networks GmbH
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

CPE = "cpe:/a:teamspeak:teamspeak3";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117227");
  script_version("2021-02-16T07:03:19+0000");
  script_tag(name:"last_modification", value:"2021-02-16 12:02:05 +0000 (Tue, 16 Feb 2021)");
  script_tag(name:"creation_date", value:"2021-02-16 07:02:05 +0000 (Tue, 16 Feb 2021)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_name("TeamSpeak 3 Server < 3.13.3 Privilege Escalation Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Privilege escalation");
  script_dependencies("gb_teamspeak_detect.nasl");
  script_mandatory_keys("teamspeak3_server/detected");

  script_xref(name:"URL", value:"https://community.teamspeak.com/t/teamspeak-server-3-13-3-important-security-update/15013");

  script_tag(name:"summary", value:"TeamSpeak 3 server is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"TeamSpeak 3 server version prior to 3.13.3.");

  script_tag(name:"solution", value:"Update TeamSpeak 3 server to version 3.13.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_in_range( version:vers, test_version:"3.0", test_version2:"3.13.2" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.13.3" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

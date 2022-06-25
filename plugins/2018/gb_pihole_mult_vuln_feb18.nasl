###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pihole_mult_vuln_feb18.nasl 8857 2018-02-18 12:18:34Z cfischer $
#
# Pi-hole Ad-Blocker < 3.3 Multiple Vulnerabilities
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:pihole:web";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108343");
  script_version("$Revision: 8857 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-02-18 13:18:34 +0100 (Sun, 18 Feb 2018) $");
  script_tag(name:"creation_date", value:"2018-02-18 11:43:37 +0100 (Sun, 18 Feb 2018)");
  script_name("Pi-hole Ad-Blocker < 3.3 Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH");
  script_dependencies("gb_pihole_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Pi-hole/installed");

  script_xref(name:"URL", value:"https://pi-hole.net/2018/02/14/pi-hole-v3-3-released-its-extra-special/");
  script_xref(name:"URL", value:"https://github.com/pi-hole/AdminLTE/pull/674");

  script_tag(name:"summary", value:"This host is installed with the Pi-hole Ad-Blocker and
  is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of the Detection-NVT and check if the version is vulnerable.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - not using parameterized SQL queries.

  - XSS attack vectors in the php/auth.php and php/debug.php files.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attackers to conduct SQL injection and XSS attacks.

  Impact Level: Application/System.");

  script_tag(name:"affected", value:"Versions of the Pi-hole Ad-Blocker Web-Interface prior to 3.3.");

  script_tag(name:"solution", value:"Update the Pi-hole Ad-Blocker to version 3.3 or later.

  For updates refer to https://pi-hole.net");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"3.3" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.3" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

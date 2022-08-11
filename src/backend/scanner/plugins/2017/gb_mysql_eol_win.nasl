###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mysql_eol_win.nasl 12175 2018-10-31 06:20:00Z ckuersteiner $
#
# MySQL End Of Life Detection (Windows)
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108189");
  script_version("$Revision: 12175 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-31 07:20:00 +0100 (Wed, 31 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-06-26 13:48:20 +0200 (Mon, 26 Jun 2017)");
  script_name("MySQL End Of Life Detection (Windows)");
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_mandatory_keys("MySQL/installed", "Host/runs_windows");
  script_require_ports("Services/mysql", 3306);

  script_xref(name:"URL", value:"https://www.mysql.com/support/eol-notice.html");
  script_xref(name:"URL", value:"https://en.wikipedia.org/wiki/MySQL#Release_history");

  script_tag(name:"summary", value:"The MySQL version on the remote host has reached the end of life and should
  not be used anymore.");
  script_tag(name:"impact", value:"An end of life version of MySQL is not receiving any security updates from the vendor. Unfixed security vulnerabilities
  might be leveraged by an attacker to compromise the security of this host.");
  script_tag(name:"solution", value:"Update the MySQL version on the remote host to a still supported version.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("misc_func.inc");
include("products_eol.inc");
include("version_func.inc");
include("host_details.inc");

# mysql:mysql is <= 5.5.9, newer versions have oracle:mysql
cpe_list = make_list( "cpe:/a:mysql:mysql", "cpe:/a:oracle:mysql" );

if( ! infos = get_all_app_ports_from_list( cpe_list:cpe_list ) ) exit( 0 );
cpe = infos['cpe'];
port = infos['port'];

if( ! version = get_app_version( cpe:cpe, port:port ) ) exit( 0 );

if( ret = product_reached_eol( cpe:cpe, version:version ) ) {
  report = build_eol_message( name:"MySQL",
                              cpe:cpe,
                              version:version,
                              eol_version:ret["eol_version"],
                              eol_date:ret["eol_date"],
                              eol_type:"prod" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

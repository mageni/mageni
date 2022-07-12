###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openvas_administrator_auth_bypass_11_13.nasl 13876 2019-02-26 12:04:06Z cfischer $
#
# OpenVAS Administrator Authentication Bypass
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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
###############################################################################

CPE = "cpe:/a:openvas:openvas_administrator";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103828");
  script_version("$Revision: 13876 $");
  script_cve_id("CVE-2013-6766");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-02-26 13:04:06 +0100 (Tue, 26 Feb 2019) $");
  script_tag(name:"creation_date", value:"2013-11-08 13:03:55 +0200 (Fri, 08 Nov 2013)");
  script_name("OpenVAS Administrator Authentication Bypass");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_openvas_administrator_detect.nasl", "gb_greenbone_os_detect.nasl");
  script_require_ports("Services/oap", 9393);
  script_mandatory_keys("openvas_administrator/detected");
  script_exclude_keys("greenbone/gos/detected");

  script_xref(name:"URL", value:"http://openvas.org/OVSA20131108.html");

  script_tag(name:"impact", value:"Attackers can exploit these issues to gain unauthorized access to the
  affected application and perform certain actions.");

  script_tag(name:"vuldetect", value:"Try to bypass OAP authentication by sending a special crafted request.");

  script_tag(name:"insight", value:"A software bug in the server module 'OpenVAS Administrator' allowed to bypass the OAP
  authentication procedure. The attack vector is remotely available in case public OAP is enabled.
  In case of successful attack, the attacker gains partial rights to execute OAP commands.");

  script_tag(name:"solution", value:"Update to version 1.2.2 or 1.3.2.");

  script_tag(name:"summary", value:"The remote OpenVAS Administrator is prone to an authentication bypass.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("host_details.inc");

if( get_kb_item( "greenbone/gos/detected" ) )
  exit( 0 ); # there is an extra nvt gb_gsm_manager_auth_bypass_11_13.nasl for the gsm

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! get_app_location( port:port, cpe:CPE ) )
  exit( 0 );

soc = open_sock_tcp( port );
if( ! soc )
  exit( 0 );

req = "<get_version/><get_users/>";
send( socket:soc, data:req + '\r\n' );
res = recv( socket:soc, length:1024 );
close( soc );

if( "get_users_response status" >< res && "<user>" >< res ) {
  report = 'By sending the request "' + req + '" to the remote OAP service it was possible to bypass the authentication. Response:\n\n' + res;
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_f5_big_ip_webinterface_default_credentials.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# F5 Networks BIG-IP Webinterface Default Credentials
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105163");
  script_version("$Revision: 11872 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("F5 Networks BIG-IP Webinterface Default Credentials");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-01-09 16:30:36 +0100 (Fri, 09 Jan 2015)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Mitigation");
  script_family("Default Accounts");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_f5_big_ip_webinterface_detect.nasl");
  script_require_ports("Services/www", 443);

  script_tag(name:"summary", value:'The remote F5 BIG-IP web interface is prone to a default account authentication
bypass vulnerability.');

  script_tag(name:"impact", value:'This issue may be exploited by a remote attacker to gain
access to sensitive information or modify system configuration.');

  script_tag(name:"vuldetect", value:'Try to login with default credentials.');
  script_tag(name:"insight", value:'It was possible to login with default credentials: admin/admin');
  script_tag(name:"solution", value:'Change the password.');
  script_mandatory_keys("f5/big_ip/web_management/installed");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_kb_item("f5/big_ip/web_management/port");

if( ! port ) exit( 0 );

pd = "username=admin&passwd=admin";

req = http_post( port:port, item:'/tmui/logmein.html', data:pd );
res = http_keepalive_send_recv(port:port, data:req);

if( "BIGIPAuthCookie" >< res && "BIGIPAuthUsernameCookie" >< res )
{
  security_message( port:port );
  exit( 0 );
}

exit( 99 );


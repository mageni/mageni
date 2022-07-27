###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_netgear_GS108T_default_password.nasl 13679 2019-02-15 08:20:11Z cfischer $
#
# NETGEAR ProSAFE GS108T Default Password
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Copyright:
# Copyright (c) 2016 SCHUTZWERK GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105629");
  script_version("$Revision: 13679 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 09:20:11 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2016-04-29 11:25:48 +0200 (Fri, 29 Apr 2016)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("NETGEAR ProSAFE GS108T Default Password");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("This script is Copyright (C) 2016 SCHUTZWERK GmbH");
  script_dependencies("gb_netgear_prosafe_consolidation.nasl");
  script_mandatory_keys("netgear/prosafe/http/detected");

  script_xref(name:"URL", value:"https://www.netgear.com/support/product/GS108Tv1.aspx");

  script_tag(name:"solution", value:"Change the password.");

  script_tag(name:"summary", value:"The remote NETGEAR ProSAFE GS108T device has the default password 'password'.");

  script_tag(name:"affected", value:"NETGEAR ProSAFE GS108T devices. Other models might be also affected.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if( ! port = get_kb_item( "netgear/prosafe/http/port" ) ) exit( 0 );

req = http_post_req( port:port, url:"/login.cgi", data:"password=password&rtime=" + unixtime() + ".99", add_headers:make_array( "Content-Type", "application/x-www-form-urlencoded" ) );
res = http_keepalive_send_recv( port:port, data:req );
if( ! res ) exit( 0 );

cookie = http_get_cookie_from_header( buf:res, pattern:"Broadcom-WebSuperSmart=([^; ]+)" );
if( isnull( cookie ) ) exit( 0 );

req = http_get_req( port:port, url:"/sysinfo.html", add_headers:make_array( "Cookie", "Broadcom-WebSuperSmart=" + cookie ) );
res = http_keepalive_send_recv( port:port, data:req );

if( res =~ "^HTTP/1\.[01] 200" && "System Information" >< res && "MAC address" >< res ) {
  security_message( port:port, data:"It was possible to login with the default password 'password'" );
  exit( 0 );
}

exit( 99 );

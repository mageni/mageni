###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_lantronix_unprotected_web.nasl 11923 2018-10-16 10:38:56Z mmartin $
#
# Lantronix Devices Unprotected Web Access
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, https://www.greenbone.net
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112133");
  script_version("$Revision: 11923 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-16 12:38:56 +0200 (Tue, 16 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-11-22 11:46:00 +0100 (Wed, 22 Nov 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("Lantronix Devices Unprotected Web Access");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Default Accounts");
  script_dependencies("gb_lantronix_device_version.nasl");
  script_mandatory_keys("lantronix_device/http/detected");

  script_tag(name:"summary", value:"The Lantronix UDS1100 Device Server web interface is accessible via an unprotected HTTP connection.");
  script_tag(name:"impact", value:"Successful exploitation allows an attacker to configure and control the device.");
  script_tag(name:"solution", value:"Ensure that the Lantronix web access is protected via strong login credentials.");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");


if( ! port = get_kb_item( "lantronix_device/http/port" ) ) exit( 0 );

# Older devices are using a java based GUI and returning a 400
# exit for those here
url = "/secure/welcome.htm";
req = http_get( item:url, port:port );
res = http_send_recv( port:port, data:req, bodyonly:FALSE );
if( res !~ "^HTTP/1\.[01] 401" ) exit( 0 );

# Any user and empty password
userpass   = "root:";
userpass64 = base64( str:userpass );

added_headers = make_array( "Authorization", "Basic " + userpass64 );
req = http_get_req( port:port, url:"/secure/menu.htm", add_headers:added_headers, accept_header:"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8" );
res = http_send_recv( port:port, data:req, bodyonly:FALSE );

if( res && res =~ "^HTTP/1\.[01] 200" && "Device Server Home Page" >< res && "Configure IP address and hostname" >< res
        && "Configure global server settings" >< res && "Apply Settings" >< res && "Apply Defaults" >< res ) {
  report = "The Lantronix Device web-manager configuration could be accessed with any username and an empty password.";
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

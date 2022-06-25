###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_trend_micro_interscan_web_security_virtual_appliance_www_default_admin_password.nasl 13679 2019-02-15 08:20:11Z cfischer $
#
# Default password `adminIWSS85` for admin account (http)
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

CPE = 'cpe:/a:trendmicro:interscan_web_security_virtual_appliance';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140243");
  script_version("$Revision: 13679 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 09:20:11 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2017-04-10 16:37:30 +0200 (Mon, 10 Apr 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Default password `adminIWSS85` for admin account (http)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_family("Default Accounts");
  script_dependencies("gb_trend_micro_interscan_web_security_virtual_appliance_www_detect.nasl");
  script_require_ports("Services/www", 8443);
  script_mandatory_keys("trend_micro/InterScan/Web_Security_Virtual_Appliance/www");

  script_tag(name:"summary", value:"This script detects if the remote Trend Micro InterScan Web Security
  Virtual Appliance has a default password of `adminIWSS85` for the `admin` account.");

  script_tag(name:"solution", value:"Set a password or change the identified default password.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) ) exit( 0 );

url = '/logon.jsp';
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

user = 'admin';
pass = 'adminIWSS85';

url = '/uilogonsubmit.jsp';

data = 'wherefrom=&wronglogon=no&uid=' + user + '&passwd=' + pass + '&pwd=Log+On';

req = http_post_req( port:port,
                     url:url,
                     data:data,
                     add_headers:make_array( "Content-Type", "application/x-www-form-urlencoded" )
                   );

buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( "summary_scan" >!< buf )
  exit( 99 );

if( ! cookie = http_get_cookie_from_header( buf:buf ) )
  exit( 99 );

url = '/top.jsp?summary_scan';

if( "CSRFGuardToken" >< buf )
{
  csrf = eregmatch( pattern:'CSRFGuardToken=([^ \r\n]+)', string:buf );
  if( isnull( csrf[1] ) )
    exit( 0 );

  url += '&CSRFGuardToken=' + csrf[1];
}

req = http_get_req( port:port,
                    url:url,
                    add_headers:make_array( "Cookie", cookie)
                  );


buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( 'logout.jsp' >< buf && "Welcome,admin" >< buf )
{
  security_message( port:port, data:'It was possible to login as user `' + user + '` with password `' + pass +'`.' );
  exit( 0 );
}

exit( 99 );

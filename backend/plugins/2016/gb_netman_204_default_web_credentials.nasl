###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netman_204_default_web_credentials.nasl 12431 2018-11-20 09:21:00Z asteins $
#
# NetMan 204 Default Web Login
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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

CPE = 'cpe:/a:riello:netman_204';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140003");
  script_version("$Revision: 12431 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("NetMan 204 Default Web Login");

  script_tag(name:"impact", value:"Attackers can exploit this issue to obtain sensitive information that may lead to further attacks.");
  script_tag(name:"vuldetect", value:"Try to login with default credentials");
  script_tag(name:"solution", value:"Change the password");
  script_tag(name:"summary", value:"The remote NetMan 204 device has default credentials set.");
  script_tag(name:"solution_type", value:"Workaround");

  script_tag(name:"qod_type", value:"remote_active");

  script_tag(name:"last_modification", value:"$Date: 2018-11-20 10:21:00 +0100 (Tue, 20 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-09-28 16:35:07 +0200 (Wed, 28 Sep 2016)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_netman_204_web_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("netman_204/detected");

  exit(0);
}

include("http_func.inc");

include("misc_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );

credentials = make_list("admin","eurek");
url = '/cgi-bin/login.cgi';

foreach credential ( credentials )
{
  data = 'username=' + credential  + '&password=' + credential;

  req = http_post_req( port:port,
                       url:url,
                       data:data,
                       add_headers: make_array( "Content-Type", "application/x-www-form-urlencoded" ) );

  buf = http_send_recv( port:port, data:req, bodyonly:FALSE );

  if( buf =~ "HTTP/1\.. 200" && "session:" >< buf && "window.location.replace" >< buf )
  {
    co = eregmatch( pattern:'Set-Cookie: (session: [^\r\n]+)', string:buf );
    if( isnull( co[1] ) ) continue;

    cookie = co[1];

    url = '/cgi-bin/changepwd.cgi';
    req = http_get_req( port:port,
                        url:url,
                        add_headers: make_array( "Cookie", cookie )
                        );

    buf = http_send_recv( port:port, data:req, bodyonly:FALSE );

    if( ( ">Change password<" >< buf && ">Logout<" >< buf ) || "Another user is logged in. Please retry in a few minutes" >< buf )
    {
      security_message( port:port, data:"It was possible tp login with user `" + credential  + "` and password `" + credential  +"`" );
      exit( 0 );
    }
  }
}

exit( 99 );

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_beanshell_rce_http.nasl 10178 2018-06-13 12:50:54Z cfischer $
#
# BeanShell Remote Server Mode RCE Vulnerability (HTTP)
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108446");
  script_version("$Revision: 10178 $");
  script_tag(name:"last_modification", value:"$Date: 2018-06-13 14:50:54 +0200 (Wed, 13 Jun 2018) $");
  script_tag(name:"creation_date", value:"2018-06-13 14:51:12 +0200 (Wed, 13 Jun 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("BeanShell Remote Server Mode RCE Vulnerability (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Gain a shell remotely");
  script_dependencies("find_service.nasl", "httpver.nasl");
  script_require_ports("Services/www", 80); # No default port, assuming 80
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.beanshell.org/");
  script_xref(name:"URL", value:"http://www.beanshell.org/manual/remotemode.html");
  script_xref(name:"URL", value:"http://www.beanshell.org/manual/bshcommands.html#exec");

  script_tag(name:"summary", value:"The remote host is running the BeanShell Interpreter in remote server mode
  which is prone to a Remote Code Execution vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to gain complete control
  over the target system.");

  script_tag(name:"vuldetect", value:"The script sends a HTTP GET request and checks if the BeanShell remote session
  console is available on the target host.");

  script_tag(name:"affected", value:"BeanShell Interpreter running in remote server mode.");

  script_tag(name:"solution", value:"Restrict access to the listener or disable the remote server mode.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

url = "/";
res = http_get_cache( port:port, item:url );

if( res =~ "^HTTP/1\.[01] 200" && ( "<title>BeanShell Remote Session</title>" >< res || "<h2>BeanShell Remote Session</h2>" >< res ) ) {
  security_message( port:port, data:"The BeanShell remote session console is available at the following URL: " + report_vuln_url( port:port, url:url, url_only:TRUE ) );
  exit( 0 );
}

exit( 99 );
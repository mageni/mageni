###############################################################################
# OpenVAS Vulnerability Test
#
# TUTOS phpinfo() information disclosure
#
# Authors:
# Christian Fischer <info at schutzwerk.com>
#
# Copyright:
# Copyright (c) 2016 SCHUTZWERK GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

CPE = 'cpe:/a:tutos:tutos';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111106");
  script_version("2019-05-24T11:20:30+0000");
  script_tag(name:"last_modification", value:"2019-05-24 11:20:30 +0000 (Fri, 24 May 2019)");
  script_tag(name:"creation_date", value:"2016-06-16 16:40:16 +0200 (Thu, 16 Jun 2016)");
  script_cve_id("CVE-2008-0149");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_name("TUTOS phpinfo() information disclosure");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2016 SCHUTZWERK GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_tutos_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("tutos/installed");

  script_tag(name:"solution", value:"Delete them or restrict access to the listened files.");

  script_tag(name:"summary", value:"TUTOS allows remote attackers to read system information
  via a direct request to php/admin/phpinfo.php, which calls the phpinfo function.");

  script_tag(name:"impact", value:"Some of the information that can be gathered from this file
  includes: The username of the user who installed php, if they are a SUDO user, the IP address
  of the host, the web server version, the system version(unix / linux), and the root
  directory of the web server.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

function get_php_version( data ) {

  if( isnull( data ) ) return;

  vers = eregmatch( pattern:'>PHP Version ([^<]+)<', string:data );
  if( isnull ( vers[1] ) )
    return;
  else
    return vers[1];
}

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );
if( dir == "/" ) dir = "";
url = dir + "/php/admin/phpinfo.php";

host = http_host_name( dont_add_port:TRUE );
req = http_get( item:url, port:port );
res = http_keepalive_send_recv( port:port, data:req );
if( ! res ) exit( 0 );

if( "<title>phpinfo()</title>" >< res ) {

  # TODO: Save the output into a different KB key and update
  # gb_php_detect.nasl to use this info as well. Also remove
  # the can_host_php() from sw_tutos_detect.nasl once this is
  # done as the NVT would need to run before gb_php_detect.nasl.
  # Take care to not introduce some sort of dependency cycle.
  #  set_kb_item( name:"php/phpinfo/" + host + "/" + port + "/detected_urls", value:url );
  # phpversion = get_php_version( data:res );
  #if( ! isnull( phpversion ) )
  #  set_kb_item( name:"php/phpinfo/" + host + "/" + port + "/detected_versions", value:phpversion );

  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
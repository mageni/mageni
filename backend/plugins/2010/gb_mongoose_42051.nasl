###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mongoose_42051.nasl 13679 2019-02-15 08:20:11Z cfischer $
#
# Mongoose Slash Character Remote File Disclosure Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100735");
  script_version("$Revision: 13679 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 09:20:11 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2010-08-02 14:28:14 +0200 (Mon, 02 Aug 2010)");
  script_bugtraq_id(42051);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2009-4535");
  script_name("Mongoose Slash Character Remote File Disclosure Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Web Servers");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl", "webmirror.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/42051");
  script_xref(name:"URL", value:"http://code.google.com/p/mongoose/");

  script_tag(name:"summary", value:"Mongoose is prone to a remote file-disclosure vulnerability because it
  fails to properly sanitize user-supplied input.");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability to view the source code
  of files in the context of the server process, which may aid in further attacks.");

  script_tag(name:"affected", value:"This issue affects Mongoose 2.8. Other versions may be
  vulnerable as well.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by
  another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:8080 );
banner = get_http_banner( port:port );
if( ! banner || "Server:" >< banner ) exit( 0 );

host = http_host_name( dont_add_port:TRUE );

phps = http_get_kb_file_extensions( port:port, host:host, ext:"php" );
if( ! isnull( phps ) ) {
  phps = make_list( phps );
} else {
  phps = make_list( "/index.php" );
}

foreach php( phps ) {

  x++;
  url = php + "/";

  if( buf = http_vuln_check( port:port, url:url, pattern:"<\?(php)?", check_header:TRUE ) ) {
    if( "Content-Type: text/plain" >< buf ) {
      if( ! http_vuln_check( port:port, url:php, pattern:"<\?(php)?" ) ) {
        report = report_vuln_url( port:port, url:url );
        security_message( port:port, data:report );
        exit( 0 );
      }
    }
  }
  if( x>=3 )
    exit( 0 );
}

exit( 99 );

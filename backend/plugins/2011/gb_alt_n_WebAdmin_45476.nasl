###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_alt_n_WebAdmin_45476.nasl 12018 2018-10-22 13:31:29Z mmartin $
#
# Alt-N WebAdmin Remote Source Code Information Disclosure Vulnerability
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103007");
  script_version("$Revision: 12018 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-22 15:31:29 +0200 (Mon, 22 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-01-03 14:40:34 +0100 (Mon, 03 Jan 2011)");
  script_bugtraq_id(45476);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Alt-N WebAdmin Remote Source Code Information Disclosure Vulnerability");
  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/45476");
  script_xref(name:"URL", value:"http://www.comingchina.com/");
  script_xref(name:"URL", value:"http://www.altn.com/products/default.asp?product%5Fid=WebAdmin");
  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 1000);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_tag(name:"summary", value:"Alt-N WebAdmin is prone to a remote information-disclosure
vulnerability because it fails to properly sanitize user-
supplied input.

An attacker can exploit this vulnerability to view the source code
of files in the context of the server process. This may aid in
further attacks.

The following versions are affected:

Alt-N WebAdmin 3.3.3 U-Mail 9.8 for Windows U-Mail GateWay 9.8
for Windows");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:1000 );

foreach dir( make_list_unique( "/webadmin", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/login.wdm.";

  if( http_vuln_check( port:port, url:url, pattern:"<xsl:if", extra_check:make_list( "\{/root/RequestedPage\}" ) ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );

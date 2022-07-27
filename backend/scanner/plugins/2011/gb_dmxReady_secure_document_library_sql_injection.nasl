###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dmxReady_secure_document_library_sql_injection.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# DmxReady Secure Document Library SQL Injection Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801952");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-07-07 15:43:33 +0200 (Thu, 07 Jul 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("DmxReady Secure Document Library SQL Injection Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/102842/dmxreadysdl12-sql.txt");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to cause SQL
  Injection attack and gain sensitive information.");

  script_tag(name:"affected", value:"DmxReady Secure Document Library version 1.2");

  script_tag(name:"insight", value:"The flaw is caused by improper validation of user-supplied input
  via the 'ItemID' parameter in 'update.asp' that allows attacker to manipulate SQL
  queries by injecting arbitrary SQL code.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is running DmxReady Secure Document Library and is prone
  to SQL injection vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );
if( ! can_host_asp( port:port ) ) exit( 0 );

host = http_host_name( port:port );

foreach dir( make_list_unique("/SecureDocumentLibrary", "/", cgi_dirs(port:port))) {

  if(dir == "/") dir = "";

  req = http_get( item:dir + "/inc_securedocumentlibrary.asp", port:port );
  rcvRes = http_keepalive_send_recv( port:port, data:req );

  if( '<title>Secure Document Library</title>' >< rcvRes ) {

    url = dir + "/admin/SecureDocumentLibrary/DocumentLibraryManager/update.asp?ItemID='1";
    req2 = string( "GET ", url, " HTTP/1.1\r\n",
                   "Host: ", host, "\r\n\r\n" );
    rcvRes = http_keepalive_send_recv( port:port, data:req2 );

    if( "error '80040e14" >< rcvRes && ">Syntax error" >< rcvRes ) {
      report = report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
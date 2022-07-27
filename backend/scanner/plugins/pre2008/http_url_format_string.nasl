# OpenVAS Vulnerability Test
# Description: Format string on URI
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2004 Michel Arboi
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
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15640");
  script_version("2019-04-24T07:26:10+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-04-24 07:26:10 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_name("Format string on URI");
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright("This script is Copyright (C) 2004 Michel Arboi");
  script_family("Gain a shell remotely");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The remote web server seems to be
  vulnerable to a format string attack on the URI. An attacker might use
  this flaw to make it crash or even execute arbitrary code on this host.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP
  GET and check whether the server is vulnerable to format string attack.");

  script_tag(name:"insight", value:"Flaw is due to  the application fails to
  properly sanitize user-supplied input before including it in the format-specifier
  argument of a formatted-printing function.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute code, read the stack, or cause a segmentation fault in
  the running application, causing new behaviors that could compromise the security
  or the stability of the system.");

  script_tag(name:"solution", value:"Upgrade your software or contact your vendor
  and inform him of this vulnerability.");

  script_xref(name:"URL", value:"https://www.owasp.org/index.php/Format_string_attack");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("misc_func.inc");

port = get_http_port(default:80);
if(http_is_dead(port: port))
  exit(0);

req = http_get(item:strcat("/vt-test", rand_str(), ".html"), port:port);
soc = http_open_socket(port);
if(!soc)
  exit(0);

send(socket:soc, data:req);
r = http_recv(socket:soc);
http_close_socket(soc);

flag = 0;
flag2 = 0;

if(egrep(pattern:"[0-9a-fA-F]{8}", string:r))
  flag = 1;

soc = http_open_socket(port);
if(!soc)
  exit(0);

foreach method(make_list("GET", "HEAD", "OPTIONS", "TRACE", "MOVE", "INDEX", "MKDIR", "RMDIR", "PUT", "DELETE")) {

  foreach bad(make_list("%08x", "%s", "%#0123456x%08x%x%s%p%n%d%o%u%c%h%l%q%j%z%Z%t%i%e%g%f%a%C%S%08x%%#0123456x%%x%%s%%p%%n%%d%%o%%u%%c%%h%%l%%q%%j%%z%%Z%%t%%i%%e%%g%%f%%a%%C%%S%%08x")) {

    req2 = http_get(item:"/" + bad, port:port);
    req2 = ereg_replace(string:req2, pattern:"GET", replace:method);
    send(socket:soc, data:req2);
    r = http_recv(socket:soc);
    http_close_socket(soc);

    if(egrep(pattern:"[0-9a-fA-F]{8}", string:r))
      flag2++;

    soc = http_open_socket(port);
    if(!soc) {
      security_message(port);
      exit(0);
    }
  }
}

http_close_socket(soc);

if(http_is_dead(port: port)) {
  security_message(port:port);
  exit(0);
}

if(flag2 && ! flag) {
  security_message(port:port);
  exit(0);
}

exit(99);
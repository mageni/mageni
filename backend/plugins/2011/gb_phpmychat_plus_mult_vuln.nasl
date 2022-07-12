###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpmychat_plus_mult_vuln.nasl 12006 2018-10-22 07:42:16Z mmartin $
#
# phpMyChat Plus Multiple Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.801936");
  script_version("$Revision: 12006 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-22 09:42:16 +0200 (Mon, 22 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-05-16 15:25:30 +0200 (Mon, 16 May 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("MyChat Plus Multiple Vulnerabilities");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17213/");
  script_xref(name:"URL", value:"http://www.rxtx.nl/webapps-phpmychat-plus-1-93-multiple-vulnerabilities/");
  script_xref(name:"URL", value:"http://www.l33thackers.com/Thread-webapps-phpMyChat-Plus-1-93-Multiple-Vulnerabilities");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to cause SQL Injection
attack, gain sensitive information about the database used by the web application
or can cause arbitrary code execution inside the context of the web application.");
  script_tag(name:"affected", value:"phpMyChat Plus version 1.93");
  script_tag(name:"insight", value:"The flaws are due to:

  - Improper sanitization of user supplied input through the 'CookieUsername'
  and 'CookieStatus' parameter in Cookie.

  - Improper sanitization of user supplied input through the 'pmc_password'
  parameter in a printable action to avatar.php.");
  script_tag(name:"solution", value:"Upgrade to version 1.94 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"This host is running MyChat Plus and is prone to multiple
vulnerabilities.");
  script_xref(name:"URL", value:"http://sourceforge.net/projects/phpmychat");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!can_host_php(port:port)){
  exit(0);
}

foreach dir( make_list_unique( "/plus", "/phpMyChat", "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  res = http_get_cache(item:string(dir,"/index.php"), port:port);

  if("<TITLE>My WonderfulWideWeb Chat - phpMyChat-Plus</TITLE>" >< res)
  {
    req = http_get(item:string(dir, '/avatar.php?pmc_password="' +
                   '><script>alert("XSS-TEST")</script>'), port:port);

    res = http_keepalive_send_recv(port:port, data:req);

    if(res =~ "HTTP/1\.. 200" && '<script>alert("XSS-TEST")</script>' >< res)
    {
      security_message(port);
      exit(0);
    }
  }
}

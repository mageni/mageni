###############################################################################
# OpenVAS Vulnerability Test
#
# APC PowerChute Network Shutdown 'security/applet' Cross Site Scripting Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.902578");
  script_version("2019-05-17T12:32:34+0000");
  script_tag(name:"last_modification", value:"2019-05-17 12:32:34 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2011-09-30 15:58:03 +0200 (Fri, 30 Sep 2011)");
  script_bugtraq_id(33924);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("APC PowerChute Network Shutdown 'security/applet' Cross Site Scripting Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/34066");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/48973");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/501255");
  script_xref(name:"URL", value:"http://www.dsecrg.com/pages/vul/show.php?id=82");
  script_xref(name:"URL", value:"http://nam-en.apc.com/app/answers/detail/a_id/9539");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 3052);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to insert arbitrary
  HTML and script code, which will be executed in a user's browser session in
  the context of an affected site.");

  script_tag(name:"affected", value:"APC PowerChute Business Edition Shutdown 6.0.0, 7.0.1
  and 7.0.2.");

  script_tag(name:"insight", value:"The flaw is caused by improper validation of user-supplied
  input passed via the 'referrer' parameter in 'security/applet', which allows
  attackers to execute arbitrary HTML and script code on the web server.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"The host is running APC PowerChute Network Shutdown and is
  prone to cross site scripting vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:3052);

res = http_get_cache(item:"/security/loginform",  port:port);

if("PowerChute Business Edition" >< res)
{
  url = '/security/applet?referrer="><script>alert(document.cookie)</script>';

  if(http_vuln_check(port: port, url: url, check_header: TRUE,
     pattern:"><script>alert\(document\.cookie\)</script>")) {
    report = report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
  }
}

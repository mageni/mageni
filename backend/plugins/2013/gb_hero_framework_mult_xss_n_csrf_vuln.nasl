###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hero_framework_mult_xss_n_csrf_vuln.nasl 11582 2018-09-25 06:26:12Z cfischer $
#
# Hero Framework Cross-Site Scripting and Request Forgery Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803155");
  script_version("$Revision: 11582 $");
  script_bugtraq_id(57035);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-25 08:26:12 +0200 (Tue, 25 Sep 2018) $");
  script_tag(name:"creation_date", value:"2013-01-16 14:02:15 +0530 (Wed, 16 Jan 2013)");
  script_name("Hero Framework Cross-Site Scripting and Request Forgery Vulnerabilities");

  script_xref(name:"URL", value:"http://secunia.com/advisories/51668");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57035");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/80796");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/119470");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2013/Jan/62");
  script_xref(name:"URL", value:"http://www.darksecurity.de/advisories/2012/SSCHADV2012-023.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  HTML and script code in a user's browser session in context of an affected site.");
  script_tag(name:"affected", value:"Hero Framework version 3.76");
  script_tag(name:"insight", value:"- Input passed to the 'q' parameter in search and 'username'
  parameter in users/login (when 'errors' is set to 'true') is not properly
  sanitised before being returned to the user.

  - The application allows users to perform certain actions via HTTP requests
  without performing any validity checks to verify the requests.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is installed with Hero Framework and is prone to
  multiple cross site scripting and CSRF vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port)){
  exit(0);
}

foreach dir (make_list_unique("/", "/hero_os", "/framework", "/hero", cgi_dirs(port:port))) {

  if(dir == "/") dir = "";
  url = dir + "/index.php";
  res = http_get_cache( item:url, port:port );
  if( ! res ) continue;

  if( res =~ "HTTP/1.. 200" && ">Welcome to Hero!<" >< res &&
      '>Hero</' >< res && '>Member Login<' >< res ) {

    url = string(dir, '/users/login?errors=true&username=";></style><' +
                 '/script><script>alert(document.cookie)</script>');

    if(http_vuln_check(port:port, url:url, check_header:TRUE,
       pattern:"</script><script>alert\(document\.cookie\)</script>",
       extra_check:">Password<"))
    {
      report = report_vuln_url( port:port, url:url );
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

exit(99);

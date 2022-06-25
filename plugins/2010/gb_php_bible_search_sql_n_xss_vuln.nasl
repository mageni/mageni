###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_bible_search_sql_n_xss_vuln.nasl 14326 2019-03-19 13:40:32Z jschulte $
#
# PHP Bible Search 'bible.php' SQL Injection and Cross Site Scripting Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801401");
  script_version("$Revision: 14326 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:40:32 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-07-12 09:42:32 +0200 (Mon, 12 Jul 2010)");
  script_cve_id("CVE-2010-2616", "CVE-2010-2617");
  script_bugtraq_id(41197);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("PHP Bible Search 'bible.php' SQL Injection and Cross Site Scripting Vulnerabilities");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/59842");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/59843");
  script_xref(name:"URL", value:"http://www.packetstormsecurity.com/1006-exploits/phpbiblesearch-sqlxss.txt");

  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation could allow the attackers to view, add,
  modify or delete information in the back-end database amd to execute arbitrary
  HTML and script code in a user's browser session in the context of an affected site.");
  script_tag(name:"affected", value:"PHP Bible Search version 0.99");
  script_tag(name:"insight", value:"Input passed to the 'chapter' parameter in 'bible.php' script is
  not properly sanitised before being returned to the user.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"The host is running PHP Bible Search and is prone to SQL
  injection and cross site scripting vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

phpPort = get_http_port(default:80);

if(!can_host_php(port:phpPort)){
  exit(0);
}

foreach dir (make_list_unique("/phpbiblesearch", "/" , cgi_dirs(port:phpPort)))
{

  if(dir == "/") dir = "";

  sndReq = http_get(item: dir + "/bible.php", port:phpPort);
  rcvRes = http_keepalive_send_recv(port:phpPort, data:sndReq);

  if(">PHP Bible Search ::<" >< rcvRes)
  {
    sndReq = http_get(item:string(dir, "/bible.php?string=&book=2&chapter=" +
                        "<script>alert('OpenVAS-XSS-Testing')</script>"), port:phpPort);
    rcvRes = http_keepalive_send_recv(port:phpPort, data:sndReq);
    if((rcvRes =~ "HTTP/1\.. 200" && "OpenVAS-XSS-Testing" >< rcvRes))
    {
      security_message(port:phpPort);
      exit(0);
    }
  }
}

exit(99);

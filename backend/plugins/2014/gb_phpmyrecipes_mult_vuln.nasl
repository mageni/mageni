###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpmyrecipes_mult_vuln.nasl 33983 2014-01-03 13:15:19Z jan$
#
# phpMyRecipes Multiple Vulnerabilities
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804056");
  script_version("$Revision: 11402 $");
  script_cve_id("CVE-2014-9347", "CVE-2014-9440");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 11:13:36 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2014-01-03 13:15:19 +0530 (Fri, 03 Jan 2014)");
  script_name("phpMyRecipes Multiple Vulnerabilities");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
  HTML or script code, inject or manipulate SQL queries in the back-end
  database, allowing for the manipulation or disclosure of arbitrary data
  and conduct other attacks.");

  script_tag(name:"affected", value:"phpMyRecipes version 1.x.x");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  An improper validation of user supplied inputs passed via

  - 'r_id' parameter to index.php and textrecipe.php.

  - 'from' parameter to ingredients.php.

  - 'categories' parameter to dosearch.php.

  - 'r_arecipes' parameter to domenutext.php.

  - All the POST parameters.

  All forms were missing CSRF tokens.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request and check whether it is able to read
  the cookie or not.");

  script_tag(name:"summary", value:"This host is installed with phpMyRecipes and is prone to multiple
  vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/124536");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/phpmyrecipes-1xx-xss-csrf-sql-injection");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

phpPort = get_http_port(default:80);

if(!can_host_php(port:phpPort)){
  exit(0);
}

foreach dir (make_list_unique("/", "/phpmyrecipes", "/recipes", cgi_dirs(port:phpPort)))
{

  if(dir == "/") dir = "";

  res = http_get_cache(item:string(dir,"/index.php"),  port:phpPort);

  if('>phpMyRecipes' >< res)
  {
    url = dir + '/login.php';

    postData = 'username="><script>alert(document.cookie)</script>';
    host = http_host_name(port:phpPort);
    sndReq = string("POST ", url, " HTTP/1.1\r\n",
                    "Host: ", host, "\r\n",
                    "Content-Type: application/x-www-form-urlencoded\r\n",
                    "Content-Length: ", strlen(postData), "\r\n",
                    "\r\n", postData, "\r\n");
    rcvRes = http_keepalive_send_recv(port:phpPort, data:sndReq, bodyonly:FALSE);

    if(rcvRes =~ "^HTTP/1\.[01] 200" && '><script>alert(document.cookie)</script>' >< rcvRes)
    {
      security_message(port:phpPort);
      exit(0);
    }
  }
}

exit(99);

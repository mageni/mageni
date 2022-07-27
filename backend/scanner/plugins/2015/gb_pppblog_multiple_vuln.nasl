###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pppblog_multiple_vuln.nasl 11452 2018-09-18 11:24:16Z mmartin $
#
# pppBLOG Multiple Vulnerabilities
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805647");
  script_version("$Revision: 11452 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-18 13:24:16 +0200 (Tue, 18 Sep 2018) $");
  script_tag(name:"creation_date", value:"2015-06-09 10:40:36 +0530 (Tue, 09 Jun 2015)");
  script_tag(name:"qod_type", value:"exploit");
  script_name("pppBLOG Multiple Vulnerabilities");

  script_tag(name:"summary", value:"The host is installed with pppBLOG
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"Multiple flaws exist as,

  - Input passed to the 'search.php' script is not properly sanitised before
    being returned to the user.

  - Application does not restrict access to sensitive files.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain access to potentially sensitive information and execute
  arbitrary script code in a user's browser within the trust relationship
  between their browser and the server.");

  script_tag(name:"affected", value:"pppBLOG version 0.3.11");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/132156");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

pbPort = get_http_port(default:80);

if(!can_host_php(port:pbPort)){
  exit(0);
}

foreach dir (make_list_unique("/", "/pppblog", "/ppp",  "/blog", cgi_dirs(port:pbPort)))
{

  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache(item:string(dir,"/index.php"), port:pbPort);

  if("Powered by pppBlog" >< rcvRes && 'content="pppBLOG' >< rcvRes)
  {
    url = dir + "/search.php?q=1%27()%26%25%3CScRiPt%20%3Eprompt(document.cookie)%3C/ScRiPt%3E";

    if(http_vuln_check(port:pbPort, url:url,
                       pattern:"<ScRiPt >prompt\(document\.cookie\)</ScRiPt>",
                       extra_check:">pppBLOG"))
    {
      report = report_vuln_url( port:pbPort, url:url );
      security_message(port:pbPort, data:report);
      exit(0);
    }
  }
}

exit(99);

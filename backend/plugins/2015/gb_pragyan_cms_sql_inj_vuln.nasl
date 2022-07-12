###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pragyan_cms_sql_inj_vuln.nasl 14117 2019-03-12 14:02:42Z cfischer $
#
# Pragyan CMS SQL Injection Vulnerability
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.805159");
  script_version("$Revision: 14117 $");
  script_cve_id("CVE-2015-1471");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 15:02:42 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-04-03 11:17:18 +0530 (Fri, 03 Apr 2015)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("Pragyan CMS SQL Injection Vulnerability");

  script_tag(name:"summary", value:"The host is installed with Pragyan
  CMS is prone to sql injection vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able execute sql query or not.");

  script_tag(name:"insight", value:"Flaw is due to the userprofile.lib.php
  script not properly sanitizing user-supplied input appended to 'user:#'
  in the URL.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to inject or manipulate SQL queries in the back-end database,
  allowing for the manipulation or disclosure of arbitrary data.");

  script_tag(name:"affected", value:"Pragyan CMS version 3.0, Prior versions
  may also be affected.");

  script_tag(name:"solution", value:"As a workaround locate the file
  userprofile.lib.php and use the patch provided in the referenced link.");

  script_xref(name:"URL", value:"http://pastebin.com/ip2gGYuS");

  script_tag(name:"solution_type", value:"Mitigation");
  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2015/q1/402");
  script_xref(name:"URL", value:"https://github.com/delta/pragyan/issues/206");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2015/Feb/18");
  script_xref(name:"URL", value:"http://sroesemann.blogspot.de/2015/01/sroeadv-2015-11.html");
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

http_port = get_http_port(default:80);
if(!can_host_php(port:http_port)){
  exit(0);
}

foreach dir (make_list_unique("/", "/pragyan", "/cms", "/pragyancms", cgi_dirs(port:http_port)))
{

  if( dir == "/" ) dir = "";

  sndReq = http_get(item:string(dir, "/home/+login"),  port:http_port);
  rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq);

  if (">Pragyan CMS" >< rcvRes && "Login<" >< rcvRes)
  {
    url = dir + "/user:1'SQL-INJECTION-TEST";

    if(http_vuln_check(port:http_port, url:url, check_header:FALSE,
       pattern:"You have an error in your SQL syntax",
       extra_check: "SQL-INJECTION-TEST"))
    {
      security_message(port:http_port);
      exit(0);
    }
  }
}

exit(99);

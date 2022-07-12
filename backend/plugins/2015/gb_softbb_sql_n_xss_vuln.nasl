###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_softbb_sql_n_xss_vuln.nasl 11424 2018-09-17 08:03:52Z mmartin $
#
# SoftBB 'post' Parameter Multiple Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.805158");
  script_version("$Revision: 11424 $");
  script_cve_id("CVE-2014-9560", "CVE-2014-9561");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-17 10:03:52 +0200 (Mon, 17 Sep 2018) $");
  script_tag(name:"creation_date", value:"2015-04-02 13:59:06 +0530 (Thu, 02 Apr 2015)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("SoftBB 'post' Parameter Multiple Vulnerabilities");

  script_tag(name:"summary", value:"The host is installed with SoftBB
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able execute sql query or not.");

  script_tag(name:"insight", value:"The flaws are due to the
  /redir_last_post_list.php script not properly sanitizing user-supplied
  input to the 'post' parameter.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to execute arbitrary HTML and script code and inject or manipulate
  SQL queries in the back-end database, allowing for the manipulation or
  disclosure of arbitrary data.");

  script_tag(name:"affected", value:"SoftBB version 0.1.3, Prior version may
  also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/129888");

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

foreach dir (make_list_unique("/", "/softbb", "/cms", cgi_dirs(port:http_port)))
{

  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache(item:string(dir, "/index.php"),  port:http_port);

  if ("Copyright SoftBB" >< rcvRes)
  {
    url = dir + "/redir_last_post_list.php?post='SQL-INJECTION-TEST";

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

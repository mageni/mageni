###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_Milw0rm_sql_inj_vuln.nasl 2015-06-02 17:26:49 +0530 Jun$
#
# Milw0rm Clone Script SQL Injection Vulnerability
#
# Authors:
# Deependra Bapna <bdeepednra@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.805397");
  script_version("$Revision: 11452 $");
  script_cve_id("CVE-2015-4137");
  script_bugtraq_id(74745);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-18 13:24:16 +0200 (Tue, 18 Sep 2018) $");
  script_tag(name:"creation_date", value:"2015-06-02 17:26:49 +0530 (Tue, 02 Jun 2015)");
  script_name("Milw0rm Clone Script SQL Injection Vulnerability");

  script_tag(name:"summary", value:"The host is installed with Milw0rm
  and is prone to sql injection vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to execute sql query or not.");

  script_tag(name:"insight", value:"Flaw is due to the 'related.php' script
  not properly sanitizing user-supplied input.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject or manipulate SQL queries in the back-end database,
  allowing for the manipulation or disclosure of arbitrary data.");

  script_tag(name:"affected", value:"Milw0rm Clone Script 1.0");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"exploit");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2015/May/76");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/131981/Milw0rm-Clone-Script-1.0-SQL-Injection.html");

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

foreach dir (make_list_unique( "/", "/milw0rm", "/milworm_script", cgi_dirs(port:http_port)))
{

  if( dir == "/" ) dir = "";
  rcvRes = http_get_cache(item:string(dir, "/"),  port:http_port);

  if(rcvRes && '>iAm[i]nE<' >< rcvRes)
  {
    url = dir + "/related.php?program=1'";
    sndReq = http_get(item:url,  port:http_port);
    rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq);

    if(rcvRes && 'mysql_num_rows' >< rcvRes)
    {
       security_message(port:http_port);
       exit(0);
    }
  }
}

exit(99);

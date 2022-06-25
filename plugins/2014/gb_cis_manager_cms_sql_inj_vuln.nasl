###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cis_manager_cms_sql_inj_vuln.nasl 11402 2018-09-15 09:13:36Z cfischer $
#
# CIS Manager 'TroncoID' Parameter SQL Injection Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.804558");
  script_version("$Revision: 11402 $");
  script_cve_id("CVE-2014-2847");
  script_bugtraq_id(66590);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 11:13:36 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2014-04-28 19:58:39 +0530 (Mon, 28 Apr 2014)");
  script_name("CIS Manager 'TroncoID' Parameter SQL Injection Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/32660");
  script_xref(name:"URL", value:"http://www.cnnvd.org.cn/vulnerability/show/cv_id/2014040155");

  script_tag(name:"summary", value:"The host is installed with CIS Manager and is prone to sql injection
  vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request and check whether it is able
  execute sql query or not.");

  script_tag(name:"insight", value:"Input passed via the 'TroncoID' GET parameter to default.asp is not
  properly sanitised before being used in a sql query.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML or
  script code and manipulate SQL queries in the backend database allowing
  for the manipulation or disclosure of arbitrary data.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

http_port = get_http_port( default:80 );
if( ! can_host_asp( port:http_port ) ) exit( 0 );

foreach dir( make_list_unique( "/", "/cis", "/cms", "/cismanager", "/cismanagercms", cgi_dirs( port:http_port ) ) ) {

  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache( item:dir + "/default.asp",  port:http_port );

  if( ">CIS Manager<" >< rcvRes && ">Construtiva" >< rcvRes ) {

    url = dir + "/default.asp?TroncoID='SQLInjTest";

    if( http_vuln_check( port:http_port, url:url, check_header:TRUE, pattern:"'SQLInjTest'", extra_check:">error '80040e14'<" ) ) {
      report = report_vuln_url( port:http_port, url:url );
      security_message( port:http_port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
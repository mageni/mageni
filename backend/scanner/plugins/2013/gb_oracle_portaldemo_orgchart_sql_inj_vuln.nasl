###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_portaldemo_orgchart_sql_inj_vuln.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# Oracle Portal Demo Organization Chart SQL Injection Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.803772");
  script_version("$Revision: 11865 $");
  script_cve_id("CVE-2013-3831");
  script_bugtraq_id(63043);
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-10-21 13:54:36 +0530 (Mon, 21 Oct 2013)");
  script_name("Oracle Portal Demo Organization Chart SQL Injection Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://secunia.com/advisories/55332");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/123650");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2013/Oct/111");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpuoct2013-1899837.html");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to manipulate SQL queries
  by injecting arbitrary SQL code.");
  script_tag(name:"vuldetect", value:"Send a crafted exploit string via HTTP GET request and check whether it
  is able to read the database information or not.");
  script_tag(name:"insight", value:"Input passed via the 'p_arg_values' parameter to /pls/portal/PORTAL_DEMO.ORG
  _CHART.SHOW is not properly sanitized before being used in a sql query.");
  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");
  script_tag(name:"summary", value:"This host is running Oracle Portal Demo Organization Chart and is prone to
  sql injection vulnerability.");
  script_tag(name:"affected", value:"Oracle Portal version 11.1.1.6.0 and prior.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

foreach dir( make_list_unique( "/", "/portal", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  url = dir + "/pls/portal/PORTAL_DEMO.ORG_CHART.SHOW";

  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  if( res !~ "HTTP/1.. 200" && ">Organization Chart<" >!< res ) continue;

  url += "?p_arg_names=_max_levels&p_arg_values=1&p_arg_names=_start_with_field&p_arg_values=null" +
         "&p_arg_names=_start_with_value&p_arg_values=:p_start_with_value%27";

  if( http_vuln_check( port:port, url:url, check_header:TRUE,
      pattern:"(ORA-00933: SQL command not properly ended|Failed to parse query|SQL Call Stack)" ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );

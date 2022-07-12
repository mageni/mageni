###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_php_nuke_userlog_sql_inj_vuln.nasl 14031 2019-03-07 10:47:29Z cfischer $
#
# PHP-Nuke SQL Injection Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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

CPE = "cpe:/a:phpnuke:php-nuke";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900561");
  script_version("$Revision: 14031 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-06-02 08:16:42 +0200 (Tue, 02 Jun 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-1842");
  script_bugtraq_id(35117);
  script_name("PHP-Nuke SQL Injection Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_php_nuke_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("php-nuke/installed");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker cause SQL Injection attack,
  gain sensitive information about the database used by the web application
  or can execute arbitrary code inside the context of the web application.");

  script_tag(name:"affected", value:"PHP-Nuke version 8.0 and prior on all platforms.");

  script_tag(name:"insight", value:"The flaw is generated because the user supplied data passed into 'referer'
  header element when requesting the '/main/tracking/userLog.php' is not
  properly sanitized before it is used in an SQL query.");

  script_tag(name:"solution", value:"Upgrade to a later version.");

  script_tag(name:"summary", value:"This host is running PHP-Nuke and is prone to SQL Injection
  vulnerability.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/503845");
  script_xref(name:"URL", value:"http://gsasec.blogspot.com/2009/05/php-nuke-v80-referer-sql-injection.html");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less_equal( version:vers, test_version:"8.0" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"unknown" );
  security_message(port:port, data:report );
  exit( 0 );
}

exit( 99 );
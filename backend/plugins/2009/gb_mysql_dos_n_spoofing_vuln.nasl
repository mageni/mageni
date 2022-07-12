###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mysql_dos_n_spoofing_vuln.nasl 14031 2019-03-07 10:47:29Z cfischer $
#
# MySQL Denial Of Service and Spoofing Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:mysql:mysql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801064");
  script_version("$Revision: 14031 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-12-04 14:17:59 +0100 (Fri, 04 Dec 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-4019", "CVE-2009-4028");
  script_name("MySQL Denial Of Service and Spoofing Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("mysql_version.nasl");
  script_require_ports("Services/mysql", 3306);
  script_mandatory_keys("MySQL/installed");

  script_xref(name:"URL", value:"http://bugs.mysql.com/47780");
  script_xref(name:"URL", value:"http://bugs.mysql.com/47320");
  script_xref(name:"URL", value:"http://marc.info/?l=oss-security&m=125881733826437&w=2");
  script_xref(name:"URL", value:"http://dev.mysql.com/doc/refman/5.0/en/news-5-0-88.html");

  script_tag(name:"impact", value:"Successful exploitation could allow users to cause a Denial of Service and
  man-in-the-middle attackers to spoof arbitrary SSL-based MySQL servers via a crafted certificate.");

  script_tag(name:"affected", value:"MySQL 5.0.x before 5.0.88 and 5.1.x before 5.1.41 on all running platform.");

  script_tag(name:"insight", value:"The flaws are due to:

  - mysqld does not properly handle errors during execution of certain SELECT
  statements with subqueries, and does not preserve certain null_value flags
  during execution of statements that use the 'GeomFromWKB()' function.

  - An error in 'vio_verify_callback()' function in 'viosslfactories.c', when
  OpenSSL is used, accepts a value of zero for the depth of X.509 certificates.");

  script_tag(name:"solution", value:"Upgrade to MySQL version 5.0.88 or 5.1.41.");

  script_tag(name:"summary", value:"The host is running MySQL and is prone to Denial Of Service
  and Spoofing Vulnerabilities");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://dev.mysql.com/downloads");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! sqlPort = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! mysqlVer = get_app_version( cpe:CPE, port:sqlPort ) )
  exit( 0 );

if( version_in_range( version:mysqlVer, test_version:"5.0",test_version2:"5.0.87" ) ||
    version_in_range( version:mysqlVer, test_version:"5.1",test_version2:"5.1.40" ) ) {
  report = report_fixed_ver( installed_version:mysqlVer, fixed_version:"5.0.88 or 5.1.41" );
  security_message( port:sqlPort, data:report );
  exit( 0 );
}

exit( 99 );
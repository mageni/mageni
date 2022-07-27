###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mysql_auth_bypass_vuln.nasl 14031 2019-03-07 10:47:29Z cfischer $
#
# MySQL Authenticated Access Restrictions Bypass Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.801066");
  script_version("$Revision: 14031 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-12-04 14:17:59 +0100 (Fri, 04 Dec 2009)");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-4030");
  script_name("MySQL Authenticated Access Restrictions Bypass Vulnerability");
  script_xref(name:"URL", value:"http://bugs.mysql.com/bug.php?id=32167");
  script_xref(name:"URL", value:"http://dev.mysql.com/doc/refman/5.1/en/news-5-1-41.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_dependencies("mysql_version.nasl");
  script_require_ports("Services/mysql", 3306);
  script_mandatory_keys("MySQL/installed");

  script_tag(name:"impact", value:"Successful exploitation could allow users to bypass intended access restrictions
  by calling CREATE TABLE with DATA DIRECTORY or INDEX DIRECTORY argument referring to a subdirectory.");

  script_tag(name:"affected", value:"MySQL 5.1.x before 5.1.41 on all running platform.");

  script_tag(name:"insight", value:"The flaw is due to an error while calling CREATE TABLE on a MyISAM table with modified
  DATA DIRECTORY or INDEX DIRECTORY.");

  script_tag(name:"solution", value:"Upgrade to MySQL version 5.1.41 or later.");

  script_tag(name:"summary", value:"The host is running MySQL and is prone to Access restrictions Bypass
  Vulnerability");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://dev.mysql.com/downloads");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!sqlPort = get_app_port(cpe:CPE))
  exit(0);

if(!mysqlVer = get_app_version(cpe:CPE, port:sqlPort))
  exit(0);

mysqlVer = eregmatch(pattern:"([0-9.a-z]+)", string:mysqlVer);
if(mysqlVer[1] && version_in_range(version:mysqlVer[1], test_version:"5.1",test_version2:"5.1.40")) {
  report = report_fixed_ver(installed_version:mysqlVer, fixed_version:"5.1.41");
  security_message(port:sqlPort, data:report);
  exit(0);
}

exit(99);
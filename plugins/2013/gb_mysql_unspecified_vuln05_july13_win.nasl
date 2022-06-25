###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mysql_unspecified_vuln05_july13_win.nasl 11878 2018-10-12 12:40:08Z cfischer $
#
# MySQL Unspecified vulnerabilities-05 July-2013 (Windows)
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

CPE = "cpe:/a:mysql:mysql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803727");
  script_version("$Revision: 11878 $");
  script_cve_id("CVE-2013-3811", "CVE-2013-3806", "CVE-2013-3810", "CVE-2013-3807",
                "CVE-2013-3798", "CVE-2013-3796", "CVE-2013-3795");
  script_bugtraq_id(61252, 61235, 61214, 61238, 61274, 61233, 61241);
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 14:40:08 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-07-29 17:57:32 +0530 (Mon, 29 Jul 2013)");
  script_name("MySQL Unspecified vulnerabilities-05 July-2013 (Windows)");

  script_tag(name:"summary", value:"This host is running MySQL and is prone to multiple unspecified
vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");
  script_tag(name:"insight", value:"Unspecified errors in the MySQL Server component via unknown vectors related
to InnoDB, XA Transactions, Server Privileges, MemCached, Server Optimizer and
Data Manipulation Language.");
  script_tag(name:"affected", value:"Oracle MySQL 5.6.11 and earlier on Windows");
  script_tag(name:"impact", value:"Successful exploitation will allow remote authenticated users to affect
availability via unknown vectors.");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpujuly2013-1899826.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Databases");
  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_require_ports("Services/mysql", 3306);
  script_mandatory_keys("MySQL/installed", "Host/runs_windows");
  exit(0);
}

include("misc_func.inc");
include("version_func.inc");
include("host_details.inc");

if(!sqlPort = get_app_port(cpe:CPE)) exit(0);
mysqlVer = get_app_version(cpe:CPE, port:sqlPort);

if(mysqlVer && mysqlVer =~ "^(5\.6)")
{
  if(version_in_range(version:mysqlVer, test_version:"5.6", test_version2:"5.6.11"))
  {
    security_message(sqlPort);
    exit(0);
  }
}

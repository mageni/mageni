###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mysql_unspecified_vuln04_jan14_win.nasl 34604 2014-01-21 15:25:16Z Jan$
#
# Oracle MySQL Multiple Unspecified vulnerabilities - 04 Jan14 (Windows)
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
CPE = "cpe:/a:oracle:mysql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804075");
  script_version("$Revision: 11878 $");
  script_cve_id("CVE-2014-0401", "CVE-2014-0412", "CVE-2014-0437", "CVE-2013-5908");
  script_bugtraq_id(64898, 64880, 64849, 64896);
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 14:40:08 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-01-21 15:25:16 +0530 (Tue, 21 Jan 2014)");
  script_name("Oracle MySQL Multiple Unspecified vulnerabilities - 04 Jan14 (Windows)");


  script_tag(name:"summary", value:"This host is running Oracle MySQL and is prone to multiple unspecified
vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Unspecified errors in the MySQL Server component via unknown vectors related
to InnoDB, Optimizer, Error Handling, and some unknown vectors.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to manipulate certain data
and cause a DoS (Denial of Service).");
  script_tag(name:"affected", value:"Oracle MySQL version 5.1.72 and earlier, 5.5.34 and earlier, and 5.6.14
and earlier on Windows.");
  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/56491");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpujan2014-1972949.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Databases");
  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_require_ports("Services/mysql", 3306);
  script_mandatory_keys("MySQL/installed", "Host/runs_windows");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!sqlPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!mysqlVer = get_app_version(cpe:CPE, port:sqlPort))
{
  CPE = "cpe:/a:mysql:mysql";
  if(!mysqlVer = get_app_version(cpe:CPE, port:sqlPort)){
    exit(0);
  }
}

if(mysqlVer =~ "^(5\.(1|5|6))")
{
  if(version_in_range(version:mysqlVer, test_version:"5.1", test_version2:"5.1.72") ||
     version_in_range(version:mysqlVer, test_version:"5.5", test_version2:"5.5.34") ||
     version_in_range(version:mysqlVer, test_version:"5.6", test_version2:"5.6.14"))
  {
    security_message(sqlPort);
    exit(0);
  }
}

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mysql_unspecified_vuln16_jun16_lin.nasl 12455 2018-11-21 09:17:27Z cfischer $
#
# Oracle MySQL Server Component 'Replication' Unspecified Vulnerability Jun-16 (Linux)
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.808128");
  script_version("$Revision: 12455 $");
  script_cve_id("CVE-2013-5807");
  script_bugtraq_id(63105);
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-11-21 10:17:27 +0100 (Wed, 21 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-06-03 13:42:37 +0530 (Fri, 03 Jun 2016)");
  script_name("Oracle MySQL Server Component 'Replication' Unspecified Vulnerability Jun-16 (Linux)");

  script_tag(name:"summary", value:"This host is running Oracle MySQL
  and is prone to unspecified vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"insight", value:"Unspecified error in the MySQL Server
  component via unknown vectors related to Replication.");

  script_tag(name:"affected", value:"Oracle MySQL versions 5.5.10 through
  5.5.32 and 5.6.x through 5.6.12 on Linux");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to disclose sensitive information, manipulate certain data, cause a
  DoS (Denial of Service) and bypass certain security restrictions.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/55327");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpuoct2013-1899837.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Databases");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_require_ports("Services/mysql", 3306);
  script_mandatory_keys("MySQL/installed", "Host/runs_unixoide");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!sqlPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!mysqlVer = get_app_version(cpe:CPE, port:sqlPort)){
  exit(0);
}

if(mysqlVer =~ "^(5\.(5|6))")
{
  if(version_in_range(version:mysqlVer, test_version:"5.5.10", test_version2:"5.5.32") ||
     version_in_range(version:mysqlVer, test_version:"5.6", test_version2:"5.6.12"))
  {
    security_message(sqlPort);
    exit(0);
  }
}

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mysql_information_schema_unspecified_vuln.nasl 11883 2018-10-12 13:31:09Z cfischer $
#
# MySQL Information Schema Unspecified Vulnerability
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.803482");
  script_version("$Revision: 11883 $");
  script_cve_id("CVE-2013-2378");
  script_bugtraq_id(59188);
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:31:09 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-04-22 18:27:18 +0530 (Mon, 22 Apr 2013)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_name("MySQL Information Schema Unspecified Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/53022");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpuapr2013-1899555.html");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpuapr2013-1899555.html#AppendixMSQL");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("mysql_version.nasl");
  script_require_ports("Services/mysql", 3306);
  script_mandatory_keys("MySQL/installed");
  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to affect
  confidentiality, integrity, and availability via unknown vectors.");
  script_tag(name:"affected", value:"MySQL version 5.1.x before 5.1.68 and 5.5.x before 5.5.30, and
  5.6.x before 5.6.11");
  script_tag(name:"insight", value:"Unspecified error in some unknown vectors related to Information Schema.");
  script_tag(name:"solution", value:"Upgrade to MySQL version 5.1.68 or 5.5.30 or 5.6.11 or later.");
  script_xref(name:"URL", value:"http://dev.mysql.com/downloads");
  script_tag(name:"summary", value:"The host is running MySQL and is prone to multiple unspecified
  vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!sqlPort = get_app_port(cpe:CPE)) exit(0);
mysqlVer = get_app_version(cpe:CPE, port:sqlPort);

if(mysqlVer && mysqlVer =~ "^(5\.(1|5|6))")
{
  if(version_in_range(version:mysqlVer, test_version:"5.1", test_version2:"5.1.67") ||
     version_in_range(version:mysqlVer, test_version:"5.5", test_version2:"5.5.29") ||
     version_in_range(version:mysqlVer, test_version:"5.6", test_version2:"5.6.10"))
  {
    security_message(sqlPort);
    exit(0);
  }
}

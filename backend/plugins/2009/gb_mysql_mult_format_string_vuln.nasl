###############################################################################
# OpenVAS Vulnerability Test
#
# MySQL 'sql_parse.cc' Multiple Format String Vulnerabilities
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.800842");
  script_version("2019-05-13T14:05:09+0000");
  script_tag(name:"last_modification", value:"2019-05-13 14:05:09 +0000 (Mon, 13 May 2019)");
  script_tag(name:"creation_date", value:"2009-07-17 12:47:28 +0200 (Fri, 17 Jul 2009)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_cve_id("CVE-2009-2446");
  script_bugtraq_id(35609);
  script_name("MySQL 'sql_parse.cc' Multiple Format String Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/35767");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/51614");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/504799/100/0/threaded");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_dependencies("mysql_version.nasl");
  script_require_ports("Services/mysql", 3306);
  script_mandatory_keys("MySQL/installed");

  script_tag(name:"impact", value:"Successful exploitation could allow remote authenticated users to cause a Denial
  of Service and possibly have unspecified other attacks.");

  script_tag(name:"affected", value:"MySQL version 4.0.0 to 5.0.83 on all running platform.");

  script_tag(name:"insight", value:"The flaws are due to error in the 'dispatch_command' function in sql_parse.cc
  in libmysqld/ which can caused via format string specifiers in a database name
  in a 'COM_CREATE_DB' or 'COM_DROP_DB' request.");

  script_tag(name:"solution", value:"Upgrade to MySQL version 5.1.36 or later.");

  script_tag(name:"summary", value:"The host is running MySQL and is prone to Multiple Format String
  vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("misc_func.inc");
include("version_func.inc");
include("host_details.inc");

if(!sqlPort = get_app_port(cpe:CPE))
  exit(0);

mysqlVer = get_app_version(cpe:CPE, port:sqlPort);
if(mysqlVer != NULL)
{
  if(version_in_range(version:mysqlVer, test_version:"4.0", test_version2:"5.0.83")){
    security_message(sqlPort);
  }
}

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mysql_unspecified_vuln02_oct14_win.nasl 12858 2018-12-21 08:05:36Z ckuersteiner $
#
# Oracle MySQL Multiple Unspecified vulnerabilities-02 Oct14 (Windows)
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:oracle:mysql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804781");
  script_version("$Revision: 12858 $");
  script_cve_id("CVE-2014-6559", "CVE-2014-6555", "CVE-2014-6507", "CVE-2014-6500",
                "CVE-2014-6496", "CVE-2014-6494", "CVE-2014-6491", "CVE-2014-6469",
                "CVE-2014-6464");
  script_bugtraq_id(70487, 70530, 70550, 70478, 70469, 70497, 70444, 70446, 70451);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-12-21 09:05:36 +0100 (Fri, 21 Dec 2018) $");
  script_tag(name:"creation_date", value:"2014-10-20 13:30:37 +0530 (Mon, 20 Oct 2014)");

  script_name("Oracle MySQL Multiple Unspecified vulnerabilities-02 Oct14 (Windows)");

  script_tag(name:"summary", value:"This host is running Oracle MySQL and is
  prone to multiple unspecified vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Unspecified errors in the MySQL Server
  component via unknown vectors related to C API SSL CERTIFICATE HANDLING,
  SERVER:DML, SERVER:SSL:yaSSL, SERVER:OPTIMIZER, SERVER:INNODB DML FOREIGN KEYS.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to disclose potentially sensitive information, gain escalated privileges,
  manipulate certain data, cause a DoS (Denial of Service), and compromise a
  vulnerable system.");

  script_tag(name:"affected", value:"MySQL Server version 5.5.39 and earlier,
  and 5.6.20 and earlier on Windows.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/60599");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpuoct2014-1972960.html");

  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
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
  if(!mysqlVer = get_app_version(cpe:CPE, port:sqlPort))  {
    exit(0);
  }
}

if(mysqlVer =~ "^(5\.(5|6))")
{
  if(version_in_range(version:mysqlVer, test_version:"5.5", test_version2:"5.5.39")||
     version_in_range(version:mysqlVer, test_version:"5.6", test_version2:"5.6.20"))
  {
    security_message(sqlPort);
    exit(0);
  }
}

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mysql_unspecified_vuln04_jun16_lin.nasl 12110 2018-10-26 06:58:59Z cfischer $
#
# Oracle MySQL Multiple Unspecified Vulnerabilities-04 Jun16 (Linux)
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
  script_oid("1.3.6.1.4.1.25623.1.0.808116");
  script_version("$Revision: 12110 $");
  script_cve_id("CVE-2015-2567", "CVE-2015-0511", "CVE-2015-0508", "CVE-2015-0507",
                "CVE-2015-0506", "CVE-2015-0503", "CVE-2015-0500", "CVE-2015-0498");
  script_bugtraq_id(74123, 74130, 74086, 74121, 74120, 74102, 74081, 74133);
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:58:59 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-06-03 13:42:50 +0530 (Fri, 03 Jun 2016)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Oracle MySQL Multiple Unspecified Vulnerabilities-04 Jun16 (Linux)");

  script_tag(name:"summary", value:"This host is running Oracle MySQL and is
  prone to multiple unspecified vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Unspecified errors in the MySQL Server
  component via unknown vectors related to Server : Security : Privileges,
  Server : SP, Server : InnoDB, Server : Memcached, InnoDB, Server : Partition,
  Replication and some unknown vectors.");

  script_tag(name:"impact", value:"Successful exploitation will allows an
  authenticated remote attacker to cause a denial of service.");

  script_tag(name:"affected", value:"Oracle MySQL Server 5.6.23 and earlier
  on Linux.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpuapr2015-2365600.html");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
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

if(mysqlVer =~ "^5\.6")
{
  if(version_in_range(version:mysqlVer, test_version:"5.6", test_version2:"5.6.23"))
  {
    report = 'Installed version: ' + mysqlVer + '\n';
    security_message(data:report, port:sqlPort);
    exit(0);
  }
}

exit(99);
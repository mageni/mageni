###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mariadb_access_bypass_vuln_win.nasl 8849 2018-02-16 14:02:28Z asteins $
#
# MariaDB Access Bypass Vulnerability (Windows)
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:mariadb:mariadb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112199");
  script_version("$Revision: 8849 $");
  script_cve_id("CVE-2017-15365");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-02-16 15:02:28 +0100 (Fri, 16 Feb 2018) $");
  script_tag(name:"creation_date", value:"2018-01-30 09:22:39 +0100 (Tue, 30 Jan 2018)");
  script_name("MariaDB Access Bypass Vulnerability (Windows)");

  script_tag(name:"summary", value:"This host is running MariaDB and is
  prone to an access bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of the detection NVT and check if the version is vulnerable or not.");

  script_tag(name:"insight", value:"sql/event_data_objects.cc in MariaDB allows remote authenticated users with SQL access
to bypass intended access restrictions and replicate data definition language (DDL) statements to cluster nodes by leveraging incorrect ordering of DDL replication and ACL checking.");

  script_tag(name:"impact", value:"A user with an SQL access to the server could possibly use this flaw
to perform database modification on certain cluster nodes without having privileges to perform such changes.");

  script_tag(name:"affected", value:"MariaDB before 10.1.30 and 10.2.x before 10.2.10.");

  script_tag(name:"solution", value:"Update to MariaDB 10.1.30, 10.2.10 or later. For details refer to https://mariadb.org");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1524234");
  script_xref(name:"URL", value:"https://mariadb.com/kb/en/library/mariadb-10130-release-notes/");
  script_xref(name:"URL", value:"https://mariadb.com/kb/en/library/mariadb-10210-release-notes/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_mandatory_keys("MariaDB/installed", "Host/runs_windows");
  script_require_ports("Services/mysql", 3306);
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE)) {
  exit(0);
}

if(!ver = get_app_version(cpe:CPE, port:port)) {
  exit(0);
}

if(version_is_less(version:ver, test_version:"10.1.30")) {
  VULN = TRUE;
  fix = "10.1.30";
}

if(ver =~ "^(10\.2\.)") {
  if(version_is_less(version:ver, test_version:"10.2.10")) {
    VULN = TRUE;
    fix = "10.2.10";
  }
}

if(VULN) {
  report = report_fixed_ver(installed_version:ver, fixed_version:fix);
  security_message(data:report, port:port);
  exit(0);
}

exit(0);

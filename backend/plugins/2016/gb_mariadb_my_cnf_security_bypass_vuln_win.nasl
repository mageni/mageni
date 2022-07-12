###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mariadb_my_cnf_security_bypass_vuln_win.nasl 12096 2018-10-25 12:26:02Z asteins $
#
# MariaDB 'my.conf' Security Bypass Vulnerability (Windows)
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

CPE = "cpe:/a:mariadb:mariadb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809328");
  script_version("$Revision: 12096 $");
  script_cve_id("CVE-2016-6662");
  script_bugtraq_id(92912);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 14:26:02 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-09-26 12:24:08 +0530 (Mon, 26 Sep 2016)");
  script_name("MariaDB 'my.conf' Security Bypass Vulnerability (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_require_ports("Services/mysql", 3306);
  script_mandatory_keys("MariaDB/installed", "Host/runs_windows");

  script_xref(name:"URL", value:"https://jira.mariadb.org/browse/MDEV-10465");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40360/");

  script_tag(name:"summary", value:"This host is running MariaDB and is prone
  to security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to datadir is writable by
  the mysqld server, and a user that can connect to MySQL can create 'my.cnf' in
  the datadir using 'SELECT ... OUTFILE'.");

  script_tag(name:"impact", value:"Successful exploitation will allow a local
  users to execute arbitrary code with root privileges by setting malloc_lib.");

  script_tag(name:"affected", value:"MariaDB before versions before 5.5.51,
  10.0.x before 10.0.27, and 10.1.x before 10.1.17 on Windows.");

  script_tag(name:"solution", value:"Upgrade to MariaDB version 5.5.51 or 10.0.27
  or 10.1.17 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://mariadb.org");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!mariadbPort = get_app_port(cpe:CPE)){
  exit(0);
}

mariadbVer = get_app_version(cpe:CPE, port:mariadbPort);
if(isnull(mariadbVer)){
  exit(0);
}

if(mariadbVer =~ "^(10\.1\.)")
{
  if(version_is_less(version:mariadbVer, test_version:"10.1.17"))
  {
    VULN = TRUE;
    fix = "10.1.17";
  }
}

else if(mariadbVer =~ "^(10\.0\.)")
{
  if(version_is_less(version:mariadbVer, test_version:"10.0.27"))
  {
    VULN = TRUE;
    fix = "10.0.27";
  }
}

else if(mariadbVer =~ "^(5\.)")
{
  if(version_is_less(version:mariadbVer, test_version:"5.5.51"))
  {
    VULN = TRUE;
    fix = "5.5.51";
  }
}

if(VULN)
{
  report = report_fixed_ver(installed_version:mariadbVer, fixed_version:fix);
  security_message(data:report, port:mariadbPort);
  exit(0);
}

exit(99);
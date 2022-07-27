###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mariadb_mitm_attack_vuln_feb16_win.nasl 12149 2018-10-29 10:48:30Z asteins $
#
# MariaDB Man-in-the-Middle Attack Vulnerability - Feb16 (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.806678");
  script_version("$Revision: 12149 $");
  script_cve_id("CVE-2016-2047");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-29 11:48:30 +0100 (Mon, 29 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-02-02 11:37:51 +0530 (Tue, 02 Feb 2016)");
  script_name("MariaDB Man-in-the-Middle Attack Vulnerability - Feb16 (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_require_ports("Services/mysql", 3306);
  script_mandatory_keys("MariaDB/installed", "Host/runs_windows");

  script_xref(name:"URL", value:"https://mariadb.atlassian.net/browse/MDEV-9212");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2016/01/26/3");

  script_tag(name:"summary", value:"This host is running MariaDB and is prone
  to man-in-the-middle attack vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to error within
  'ssl_verify_server_cert' function which does improper verification of the
  server hostname in the subject's Common Name (CN) or subjectAltName field
  of the X.509 certificate.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to conduct man-in-the-middle attack.");

  script_tag(name:"affected", value:"MariaDB before versions 5.5.47, 10.0.x before
  10.0.23, and 10.1.x before 10.1.10 on Windows.");

  script_tag(name:"solution", value:"Upgrade to MariaDB version 5.5.47 or 10.0.23
  or 10.1.10 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

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
  if(version_is_less(version:mariadbVer, test_version:"10.1.10"))
  {
    VULN = TRUE;
    fix = "10.1.10";
  }
}

else if(mariadbVer =~ "^(10\.0\.)")
{
  if(version_is_less(version:mariadbVer, test_version:"10.0.23"))
  {
    VULN = TRUE;
    fix = "10.0.23";
  }
}

else if(mariadbVer =~ "^(5\.)")
{
  if(version_is_less(version:mariadbVer, test_version:"5.5.47"))
  {
    VULN = TRUE;
    fix = "5.5.47";
  }
}

if(VULN)
{
  report = report_fixed_ver(installed_version:mariadbVer, fixed_version:fix);
  security_message(data:report, port:mariadbPort);
  exit(0);
}

exit(99);
###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_postgresql_code_inject_nd_dos_vuln_lin.nasl 11961 2018-10-18 10:49:40Z asteins $
#
# PostgreSQL Code Injection and Denial of Service Vulnerabilities (Linux)
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

CPE = "cpe:/a:postgresql:postgresql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808665");
  script_version("$Revision: 11961 $");
  script_cve_id("CVE-2016-5423", "CVE-2016-5424");
  script_bugtraq_id(92433, 92435);
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-18 12:49:40 +0200 (Thu, 18 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-08-30 18:03:40 +0530 (Tue, 30 Aug 2016)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("PostgreSQL Code Injection and Denial of Service Vulnerabilities (Linux)");

  script_tag(name:"summary", value:"This host is running PostgreSQL and is
  prone to code injection and denial of service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to

  - An error in certain nested CASE expressions.

  - Improper sanitization of input passed to database and role names.");

  script_tag(name:"impact", value:"Successful exploitation will allow a
  remote attacker to inject code and cause the server to crash.");

  script_tag(name:"affected", value:"PostgreSQL version before 9.1.23, 9.2.x
  before 9.2.18, 9.3.x before 9.3.14, 9.4.x before 9.4.9, and 9.5.x before
  9.5.4 on linux.");

  script_tag(name:"solution", value:"Upgrade to version 9.1.23 or 9.2.18 or
  9.3.14 or 9.4.9 or 9.5.4 or higher.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.postgresql.org/about/news/1688/");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_dependencies("postgresql_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/postgresql", 5432);
  script_mandatory_keys("PostgreSQL/installed", "Host/runs_unixoide");
  script_xref(name:"URL", value:"http://www.postgresql.org/download");
  exit(0);
}


include("misc_func.inc");
include("version_func.inc");
include("host_details.inc");

pgsqlPort = get_app_port(cpe:CPE);
if(!pgsqlPort){
  exit(0);
}

pgsqlVer = get_app_version(cpe:CPE, port:pgsqlPort);
if(isnull(pgsqlVer)){
  exit(0);
}

if(version_is_less(version:pgsqlVer, test_version:"9.1.23"))
{
  fix = "9.1.23";
  VULN = TRUE;
}

else if(pgsqlVer =~ "^(9\.2)")
{
  if(version_is_less(version:pgsqlVer, test_version:"9.2.18"))
  {
    fix = "9.2.18";
    VULN = TRUE;
  }
}

else if(pgsqlVer =~ "^(9\.3)")
{
  if(version_is_less(version:pgsqlVer, test_version:"9.3.14"))
  {
    fix = "9.3.14";
    VULN = TRUE;
  }
}

else if(pgsqlVer =~ "^(9\.4)")
{
  if(version_is_less(version:pgsqlVer, test_version:"9.4.9"))
  {
    fix = "9.4.9";
    VULN = TRUE;
  }
}

else if(pgsqlVer =~ "^(9\.5)")
{
  if(version_is_less(version:pgsqlVer, test_version:"9.5.4"))
  {
    fix = "9.5.4";
    VULN = TRUE;
  }
}

if(VULN)
{
    report = report_fixed_ver(installed_version:pgsqlVer, fixed_version:fix);
    security_message(data:report, port:pgsqlPort);
    exit(0);
}

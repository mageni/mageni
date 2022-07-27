###############################################################################
# OpenVAS Vulnerability Test
#
# PostgreSQL Remote Code Execution Vulnerability-Feb18 (Windows)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/a:postgresql:postgresql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813009");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-1058");
  script_bugtraq_id(103221);
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-03-09 13:07:37 +0530 (Fri, 09 Mar 2018)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("PostgreSQL Remote Code Execution Vulnerability-Feb18 (Windows)");

  script_tag(name:"summary", value:"This host is running PostgreSQL and is
  prone to remote code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exist because postgresql allow a
  user to modify the behavior of a query for other users in an incorrect way.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to execute arbitrary code or crash the affected application,
  resulting in denial-of-service condition.");

  script_tag(name:"affected", value:"PostgreSQL version 9.3.x before 9.3.22,
  9.4.x before 9.4.17, 9.5.x before 9.5.12, 9.6.x before 9.6.8 and 10.x before
  10.3 on Windows.");

  script_tag(name:"solution", value:"Upgrade to PostgreSQL version 10.3 or 9.6.8
  or 9.5.12 or 9.4.17 or 9.3.22 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.postgresql.org/about/news/1834");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/current/static/release-10-2.html");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/current/static/release-9-6-7.html");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/current/static/release-9-5-11.html");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/current/static/release-9-4-16.html");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/current/static/release-9-3-21.html");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_dependencies("postgresql_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("PostgreSQL/installed", "Host/runs_windows");
  script_require_ports("Services/postgresql", 5432);
  script_xref(name:"URL", value:"http://www.postgresql.org/download");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

pgsqlPort = get_app_port(cpe:CPE);
if(!pgsqlPort){
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, port:pgsqlPort, exit_no_version:TRUE)) exit(0);
pgsqlVer = infos['version'];
pgsqlPath = infos['location'];

if(pgsqlVer =~ "^(9\.3)")
{
  if(version_is_less(version:pgsqlVer, test_version:"9.3.22")){
    fix = "9.3.22";
  }
}

else if(pgsqlVer =~ "^(9\.4)")
{
  if(version_is_less(version:pgsqlVer, test_version:"9.4.17")){
    fix = "9.4.17";
  }
}

else if(pgsqlVer =~ "^(9\.5)")
{
  if(version_is_less(version:pgsqlVer, test_version:"9.5.12")){
    fix = "9.5.12";
  }
}

else if(pgsqlVer =~ "^(9\.6)")
{
  if(version_is_less(version:pgsqlVer, test_version:"9.6.8")){
    fix = "9.6.8";
  }
}

else if(pgsqlVer =~ "^(10\.)")
{
  if(version_is_less(version:pgsqlVer, test_version:"10.3")){
    fix = "10.3";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version: pgsqlVer, fixed_version: fix, install_path:pgsqlPath);
  security_message(port:pgsqlPort, data: report);
  exit(0);
}
exit(0);

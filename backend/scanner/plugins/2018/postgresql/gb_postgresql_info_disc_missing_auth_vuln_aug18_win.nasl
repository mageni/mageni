###############################################################################
# OpenVAS Vulnerability Test
#
# PostgreSQL Information Disclosure And Missing Authentication Vulnerabilities Aug18 (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.813753");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-10925");
  script_bugtraq_id(105052);
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-08-13 12:44:42 +0530 (Mon, 13 Aug 2018)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("PostgreSQL Information Disclosure And Missing Authentication Vulnerabilities Aug18 (Windows)");

  script_tag(name:"summary", value:"This host is running PostgreSQL and is
  prone to information disclosure and missing authentication vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to a missing
  authorization on certain statements involved with 'INSERT ... ON CONFLICT
  DO UPDATE' .");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to read arbitrary bytes of server memory and update other columns which should
  have been restricted otherwise.");

  script_tag(name:"affected", value:"PostgreSQL versions before 10.5, 9.6.10
  and 9.5.14 on Windows.");

  script_tag(name:"solution", value:"Upgrade to PostgreSQL version 10.5 or 9.6.10
  or 9.5.14 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.postgresql.org/about/news/1878");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/10/static/release-10-5.html#id-1.11.6.5.5");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/10/static/release-9-6-10.html#id-1.11.6.11.5");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/10/static/release-9-5-14.html#id-1.11.6.22.5");
  script_xref(name:"URL", value:"http://www.postgresql.org/download");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_dependencies("postgresql_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("PostgreSQL/installed", "Host/runs_windows");
  script_require_ports("Services/postgresql", 5432);
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

if(pgsqlVer =~ "^9\.5\.")
{
  if(version_is_less(version:pgsqlVer, test_version: "9.5.14")) {
    fix = "9.5.14";
  }
}

else if(pgsqlVer =~ "^9\.6\.")
{
  if(version_is_less(version:pgsqlVer, test_version: "9.6.10")) {
    fix = "9.6.10";
  }
}

else if (pgsqlVer =~ "^10\.")
{
  if(version_is_less(version:pgsqlVer, test_version: "10.5")) {
    fix = "10.5";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:pgsqlVer, fixed_version:fix, install_path:pgsqlPath);
  security_message(port:pgsqlPort, data: report);
  exit(0);
}

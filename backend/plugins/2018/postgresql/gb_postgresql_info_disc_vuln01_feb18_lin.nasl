###############################################################################
# OpenVAS Vulnerability Test
#
# PostgreSQL Information Disclosure Vulnerability-01 Feb18 (Linux)
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
  script_oid("1.3.6.1.4.1.25623.1.0.812957");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-1052");
  script_bugtraq_id(102987);
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-02-28 11:29:21 +0530 (Wed, 28 Feb 2018)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("PostgreSQL Information Disclosure Vulnerability-01 Feb18 (Linux)");

  script_tag(name:"summary", value:"This host is running PostgreSQL and is
  prone to a information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in the
  processing of partition keys containing multiple expressions.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  authenticated attacker to gain access to sensitive information that may aid
  in further attacks.");

  script_tag(name:"affected", value:"PostgreSQL version 10.x before
  10.2 on Linux.");

  script_tag(name:"solution", value:"Upgrade to PostgreSQL version 10.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.postgresql.org/about/news/1829");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/current/static/release-10-2.html");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_dependencies("postgresql_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("PostgreSQL/installed", "Host/runs_unixoide");
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

if(pgsqlVer =~ "^10\.")
{
  if(version_is_less(version:pgsqlVer, test_version:"10.2"))
  {
    report = report_fixed_ver(installed_version: pgsqlVer, fixed_version:"10.2", install_path:pgsqlPath);
    security_message(port:pgsqlPort, data:report);
    exit(0);
  }
}
exit(0);

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_postgresql_info_disc_vuln_dec17_lin.nasl 12142 2018-10-29 08:28:54Z cfischer $
#
# PostgreSQL Information Disclosure Vulnerability-Dec17 (Linux)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.812310");
  script_version("$Revision: 12142 $");
  script_cve_id("CVE-2017-15098");
  script_bugtraq_id(101781);
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-29 09:28:54 +0100 (Mon, 29 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-12-04 16:34:17 +0530 (Mon, 04 Dec 2017)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("PostgreSQL Information Disclosure Vulnerability-Dec17 (Linux)");

  script_tag(name:"summary", value:"This host is running PostgreSQL and is
  prone to a information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists as the functions
  json_populate_recordset and jsonb_populate_recordset are unable to handle
  malformed invalid input.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  authenticated users to send specially crafted data to trigger a rowtype mismatch
  in 'json{b}_populate_recordset' function to crash the target service or disclose
  potentially sensitive information.");

  script_tag(name:"affected", value:"PostgreSQL version 9.3.x before 9.3.20,
  9.4.x before 9.4.15, 9.5.x before 9.5.10, 9.6.x before 9.6.6 and 10.x before
  10.1 on Linux.");

  script_tag(name:"solution", value:"Upgrade to PostgreSQL version 10.1 or 9.6.6
  or 9.5.10 or 9.4.15 or 9.3.20 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.postgresql.org/about/news/1801");
  script_xref(name:"URL", value:"https://www.postgresql.org/support/security");

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
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

if(pgsqlVer =~ "^9\.3")
{
  if(version_is_less(version:pgsqlVer, test_version:"9.3.20")){
    fix = "9.3.20";
  }
}

else if(pgsqlVer =~ "^9\.4")
{
  if(version_is_less(version:pgsqlVer, test_version:"9.4.15")){
    fix = "9.4.15";
  }
}

else if(pgsqlVer =~ "^9\.5")
{
  if(version_is_less(version:pgsqlVer, test_version:"9.5.10")){
    fix = "9.5.10";
  }
}

else if(pgsqlVer =~ "^9\.6")
{
  if(version_is_less(version:pgsqlVer, test_version:"9.6.6")){
    fix = "9.6.6";
  }
}

else if(pgsqlVer =~ "^10\.")
{
  if(version_is_less(version:pgsqlVer, test_version:"10.1")){
    fix = "10.1";
  }
}


if(fix)
{
  report = report_fixed_ver(installed_version: pgsqlVer, fixed_version: fix, install_path:pgsqlPath);
  security_message(port:pgsqlPort, data: report);
  exit(0);
}
exit(0);

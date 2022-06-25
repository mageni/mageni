###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_postgresql_mult_vuln_aug17_lin.nasl 11836 2018-10-11 08:56:08Z mmartin $
#
# PostgreSQL Multiple Vulnerabilities - August17 (Linux)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.811580");
  script_version("$Revision: 11836 $");
  script_cve_id("CVE-2017-7546", "CVE-2017-7547");
  script_bugtraq_id(100275, 100278);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-11 10:56:08 +0200 (Thu, 11 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-08-17 12:50:23 +0530 (Thu, 17 Aug 2017)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("PostgreSQL Multiple Vulnerabilities - August17 (Linux)");

  script_tag(name:"summary", value:"This host is running PostgreSQL and is
  prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - libpq, and by extension any connection driver that utilizes libpq, ignores
    empty passwords and does not transmit them to the server.

  - User had access to see the options in pg_user_mappings even if the user did not
    have the USAGE permission on the associated foreign server.");

  script_tag(name:"impact", value:"Successful exploitation will allow a
  remote attacker to bypass security and obtain sensitive information.");

  script_tag(name:"affected", value:"PostgreSQL version 9.2.x before 9.2.22,
  9.3.x before 9.3.18, 9.4.x before 9.4.13, and 9.5.x before 9.5.8 and 9.6.x
  before 9.6.4 on Linux.");

  script_tag(name:"solution", value:"Upgrade to version 9.2.22 or 9.3.18 or
  9.4.13 or 9.5.8 or 9.6.4 or higher.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.postgresql.org/about/news/1772/");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/current/static/release-9-2-22.html");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/current/static/release-9.5.8.html");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/current/static/release-9.4.13.html");

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

if(!pgsqlVer = get_app_version(cpe:CPE, port:pgsqlPort)){
  exit(0);
}

if(pgsqlVer =~ "^(9\.2)")
{
  if(version_is_less(version:pgsqlVer, test_version:"9.2.22")){
    fix = "9.2.22";
  }
}

else if(pgsqlVer =~ "^(9\.3)")
{
  if(version_is_less(version:pgsqlVer, test_version:"9.3.18")){
    fix = "9.3.18";
  }
}

else if(pgsqlVer =~ "^(9\.4)")
{
  if(version_is_less(version:pgsqlVer, test_version:"9.4.13")){
    fix = "9.4.13";
  }
}

else if(pgsqlVer =~ "^(9\.5)")
{
  if(version_is_less(version:pgsqlVer, test_version:"9.5.8")){
    fix = "9.5.8";
  }
}

else if(pgsqlVer =~ "^(9\.6)")
{
  if(version_is_less(version:pgsqlVer, test_version:"9.6.4")){
    fix = "9.6.4";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:pgsqlVer, fixed_version:fix);
  security_message(data:report, port:pgsqlPort);
  exit(0);
}
exit(0);

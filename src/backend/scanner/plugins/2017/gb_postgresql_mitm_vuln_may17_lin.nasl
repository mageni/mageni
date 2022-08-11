###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_postgresql_mitm_vuln_may17_lin.nasl 11863 2018-10-12 09:42:02Z mmartin $
#
# PostgreSQL Man In The Middle (MITM) Vulnerability - May17 (Linux)
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
  script_oid("1.3.6.1.4.1.25623.1.0.810992");
  script_version("$Revision: 11863 $");
  script_cve_id("CVE-2017-7485");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 11:42:02 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-05-15 16:09:12 +0530 (Mon, 15 May 2017)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("PostgreSQL Man In The Middle (MITM) Vulnerability - May17 (Linux)");

  script_tag(name:"summary", value:"This host is running PostgreSQL and is
  prone to a man-in-the-middle attack vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in the
  'libpq' component of PostgreSQL, where the 'PGREQUIRESSL' environment
  variable was no longer enforcing a SSL/TLS connection to a PostgreSQL server.");

  script_tag(name:"impact", value:"Successful exploitation will allow a
  man-in-the-middle attacker to strip the SSL/TLS protection from a connection
  between a client and a server.");

  script_tag(name:"affected", value:"PostgreSQL version 9.3.x before 9.3.17,
  9.4.x before 9.4.12, 9.5.x before 9.5.7, and 9.6.x before 9.6.3 on Linux.");

  script_tag(name:"solution", value:"Upgrade to PostgreSQL version 9.3.17 or
  9.4.12 or 9.5.7 or 9.6.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.postgresql.org/about/news/1746");
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

if(pgsqlVer =~ "^(9\.3)")
{
  if(version_is_less(version:pgsqlVer, test_version:"9.3.17")){
    fix = "9.3.17";
  }
}

else if(pgsqlVer =~ "^(9\.4)")
{
  if(version_is_less(version:pgsqlVer, test_version:"9.4.12")){
    fix = "9.4.12";
  }
}

else if(pgsqlVer =~ "^(9\.5)")
{
  if(version_is_less(version:pgsqlVer, test_version:"9.5.7")){
    fix = "9.5.7";
  }
}

else if(pgsqlVer =~ "^(9\.6)")
{
  if(version_is_less(version:pgsqlVer, test_version:"9.6.3")){
    fix = "9.6.3";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:pgsqlVer, fixed_version:fix);
  security_message(data:report, port:pgsqlPort);
  exit(0);
}

exit(99);

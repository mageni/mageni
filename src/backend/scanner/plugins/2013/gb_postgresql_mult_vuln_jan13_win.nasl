###############################################################################
# OpenVAS Vulnerability Test
#
# PostgreSQL 'xml_parse()' And 'xslt_process()' Multiple Vulnerabilities (Windows)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803219");
  script_version("2019-05-20T11:12:48+0000");
  script_cve_id("CVE-2012-3488", "CVE-2012-3489");
  script_bugtraq_id(55072, 55074);
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2019-05-20 11:12:48 +0000 (Mon, 20 May 2019)");
  script_tag(name:"creation_date", value:"2013-01-24 17:08:52 +0530 (Thu, 24 Jan 2013)");
  script_name("PostgreSQL 'xml_parse()' And 'xslt_process()' Multiple Vulnerabilities (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/50218");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1027408");
  script_xref(name:"URL", value:"http://www.postgresql.org/about/news/1407");
  script_xref(name:"URL", value:"http://www.postgresql.org/support/security");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("postgresql_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/postgresql", 5432);
  script_mandatory_keys("PostgreSQL/installed", "Host/runs_windows");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to modify data, obtain sensitive
  information or trigger outbound traffic to arbitrary external hosts.");

  script_tag(name:"affected", value:"PostgreSQL versions 8.3 before 8.3.20, 8.4 before 8.4.13,
  9.0 before 9.0.9, and 9.1 before 9.1.5 on Windows");

  script_tag(name:"insight", value:"- An error exists within the 'xml_parse()' function when parsing DTD data
  within XML documents.

  - An error exists within the 'xslt_process()' when parsing XSLT style sheets.");

  script_tag(name:"solution", value:"Upgrade to PostgreSQL 8.3.20, 8.4.13, 9.0.9 or 9.1.5 or later.");

  script_tag(name:"summary", value:"This host is installed with PostgreSQL and is prone to multiple
  vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("misc_func.inc");
include("version_func.inc");
include("host_details.inc");

if(!pgsqlPort = get_app_port(cpe:CPE)) exit(0);

pgsqlVer = get_app_version(cpe:CPE, port:pgsqlPort);
if(!pgsqlVer || pgsqlVer !~ "^[89]\."){
  exit(0);
}

if(version_in_range(version:pgsqlVer, test_version:"8.3", test_version2:"8.3.19") ||
   version_in_range(version:pgsqlVer, test_version:"8.4", test_version2:"8.4.12") ||
   version_in_range(version:pgsqlVer, test_version:"9.0", test_version2:"9.0.8") ||
   version_in_range(version:pgsqlVer, test_version:"9.1", test_version2:"9.1.4")){
  security_message(port:pgsqlPort);
}

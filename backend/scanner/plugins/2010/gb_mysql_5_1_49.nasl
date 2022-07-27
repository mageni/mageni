###############################################################################
# OpenVAS Vulnerability Test
#
# Oracle MySQL Prior to 5.1.49 Multiple Denial Of Service Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:mysql:mysql";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100785");
  script_version("2019-05-13T14:05:09+0000");
  script_tag(name:"last_modification", value:"2019-05-13 14:05:09 +0000 (Mon, 13 May 2019)");
  script_tag(name:"creation_date", value:"2010-09-07 15:26:31 +0200 (Tue, 07 Sep 2010)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_cve_id("CVE-2010-3677");
  script_bugtraq_id(42646, 42633, 42643, 42598, 42596, 42638, 42599, 42625);

  script_name("Oracle MySQL Prior to 5.1.49 Multiple Denial Of Service Vulnerabilities");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/42646");
  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/42633");
  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/42643");
  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/42598");
  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/42596");
  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/42638");
  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/42599");
  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/42625");
  script_xref(name:"URL", value:"http://bugs.mysql.com/bug.php?id=54575");
  script_xref(name:"URL", value:"http://dev.mysql.com/doc/refman/5.1/en/news-5-1-49.html");
  script_xref(name:"URL", value:"http://www.mysql.com/");

  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("mysql_version.nasl");
  script_require_ports("Services/mysql", 3306);
  script_mandatory_keys("MySQL/installed");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"summary", value:"MySQL is prone to a denial-of-service vulnerability.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to crash the database, denying
  access to legitimate users.");

  script_tag(name:"affected", value:"This issue affects versions prior to MySQL 5.1.49.");

  exit(0);
}

include("misc_func.inc");
include("version_func.inc");
include("host_details.inc");

if(!sqlPort = get_app_port(cpe:CPE))
  exit(0);

if(!mysqlVer = get_app_version(cpe:CPE, port:sqlPort))
  exit(0);

mysqlVer = eregmatch(pattern:"([0-9.a-z]+)", string:mysqlVer);

if(!isnull(mysqlVer[1]) && mysqlVer[1] =~ "^5\.")
{
  if(version_is_less(version:mysqlVer[1], test_version:"5.1.49")){
    security_message(port:sqlPort);
  }
}


###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_glpi_sql_0_90_4.nasl 14175 2019-03-14 11:27:57Z cfischer $
#
# GLPI 0.90.4 SQL Injection Vulnerability
#
# Authors:
# Tameem Eissa <Tameem.Eissa@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

CPE ='cpe:/a:glpi-project:glpi';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107227");
  script_version("$Revision: 14175 $");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 12:27:57 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-06-28 14:43:29 +0200 (Wed, 28 Jun 2017)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_name("GLPI 0.90.4 SQL Injection Vulnerability");

  script_tag(name:"summary", value:"GLPI is prone to SQL Injection");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"affected", value:"GLPI 0.90.4");
  script_tag(name:"insight", value:"The attack is due to the variable dbenc which when configured by the admin to big5, it allows SQL injection in almost all the forms of the application.");
  script_tag(name:"impact", value:"Successful exploitation will allow an authenticated remote attacker to execute arbitrary
  SQL commands by using the [ELIDED] character when the database is configured to use asian encoding (BIG 5).");
  script_tag(name:"solution", value:"Update GLPI to version 9.1 or later.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_family("Web application abuses");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_glpi_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("glpi/installed");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/42262/?rss");
  script_xref(name:"URL", value:"https://vuldb.com/de/?id.102723");
  script_xref(name:"URL", value:"https://github.com/glpi-project/glpi/releases");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe:CPE)) exit(0);
if (!vers = get_app_version(cpe:CPE, port:port)) exit(0);

if (version_is_equal(version:vers, test_version:"0.90.4")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"9.1");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

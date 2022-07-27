###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_glpi_sql_0_90_2.nasl 11596 2018-09-25 09:49:46Z asteins $
#
# GLPI 0.90.2 SQL Injection Vulnerability
#
# Authors:
# Eissa Tameem <Tameem.Eissa@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107001");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_version("$Revision: 11596 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-25 11:49:46 +0200 (Tue, 25 Sep 2018) $");
  script_tag(name:"creation_date", value:"2016-05-10 14:43:29 +0200 (Tue, 10 May 2016)");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_name("GLPI 0.92.0 SQL Injection Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_glpi_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("glpi/installed");

  script_tag(name:"summary", value:"Detection of GLPI SQL Injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Update to version 0.90.3 or later.");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

CPE ='cpe:/a:glpi-project:glpi';

if(!port = get_app_port( cpe:CPE)) exit(0);
if(!vers = get_app_version( cpe:CPE, port:port)) exit(0);

if (version_is_less(version:vers, test_version:"0.90.3")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"0.90.3");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

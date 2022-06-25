# Copyright (C) 2022 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA

CPE = "cpe:/a:adobe:connect";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.819907");
  script_version("2022-01-06T05:11:00+0000");
  script_cve_id("CVE-2021-43014");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-01-06 10:37:42 +0000 (Thu, 06 Jan 2022)");
  script_tag(name:"creation_date", value:"2022-01-03 08:25:27 +0530 (Mon, 03 Jan 2022)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Adobe Connect Cross-Site Request Forgery Vulnerability (APSB21-112)");

  script_tag(name:"summary", value:"Adobe Connect CSRF Vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw is due to a cross-site request forgery
  vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to conduct arbitrary file system write.");

  script_tag(name:"affected", value:"Adobe Connect versions 11.3 and earlier.");

  script_tag(name:"solution", value:"Update Adobe Connect to version 11.4 or
  later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/connect/apsb21-112.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_adobe_connect_detect.nasl");
  script_mandatory_keys("adobe/connect/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}
include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE)) exit(0);
vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"11.4"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"11.4", install_path:path);
  security_message(data:report, port:port);
  exit(0);
}
exit(0);

# Copyright (C) 2020 Greenbone Networks GmbH
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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:horde:horde_groupware";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112752");
  script_version("2020-05-19T12:25:57+0000");
  script_tag(name:"last_modification", value:"2020-05-20 09:55:38 +0000 (Wed, 20 May 2020)");
  script_tag(name:"creation_date", value:"2020-05-19 12:24:00 +0000 (Tue, 19 May 2020)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2020-8035");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Horde Groupware Webmail < 5.2.22 XSS Vulnerability (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("horde_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("horde/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"Horde Groupware Webmail is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"insight", value:"The image view functionality is affected by a stored cross-site scripting (XSS)
  vulnerability via an SVG image upload containing a JavaScript payload.");

  script_tag(name:"impact", value:"An attacker can obtain access to a victim's webmail account by making them visit a malicious URL.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Horde Groupware Webmail before version 5.2.22.");

  script_tag(name:"solution", value:"Update to version 5.2.22 or later.");

  script_xref(name:"URL", value:"https://lists.horde.org/archives/announce/2020/001290.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version: vers, test_version: "5.2.22")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "5.2.22", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

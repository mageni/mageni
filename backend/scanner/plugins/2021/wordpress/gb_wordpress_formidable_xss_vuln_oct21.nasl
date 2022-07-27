# Copyright (C) 2021 Greenbone Networks GmbH
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

CPE = "cpe:/a:strategy11:formidable";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147083");
  script_version("2021-11-03T14:03:41+0000");
  script_tag(name:"last_modification", value:"2021-11-03 14:03:41 +0000 (Wed, 03 Nov 2021)");
  script_tag(name:"creation_date", value:"2021-11-03 07:22:41 +0000 (Wed, 03 Nov 2021)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-28 15:03:00 +0000 (Thu, 28 Oct 2021)");

  script_cve_id("CVE-2021-24884");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Formidable Forms Builder Plugin < 4.09.05 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/formidable/detected");

  script_tag(name:"summary", value:"The WordPress plugin Formidable Forms Builder is prone to a
  cross-site scripting (XSS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin allows to inject certain HTML Tags like <audio>,
  <video>, <img>, <a> and<button>. This could allow an unauthenticated, remote attacker to exploit
  a HTML-injection by injecting a malicious link. The HTML-injection may trick authenticated users
  to follow the link. If the Link gets clicked, Javascript code can be executed. The vulnerability
  is due to insufficient sanitization of the 'data-frmverify' tag for links in the web-based entry
  inspection page of affected systems. A successful exploitation in comibantion with CSRF could
  allow the attacker to perform arbitrary actions on an affected system with the privileges of the
  user. These actions include stealing the users account by changing their password or allowing
  attackers to submit their own code through an authenticated user resulting in Remote Code
  Execution. If an authenticated user who is able to edit Wordpress PHP Code in any kind, clicks
  the malicious link, PHP code can be edited.");

  script_tag(name:"affected", value:"WordPress Formidable Forms Builder version 4.09.04 and prior.");

  script_tag(name:"solution", value:"Update to version 4.09.05 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/b57dacdd-43c2-48f8-ac1e-eb8306b22533");
  script_xref(name:"URL", value:"https://raw.githubusercontent.com/Strategy11/formidable-forms/master/changelog.txt");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "4.09.05")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.09.05", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

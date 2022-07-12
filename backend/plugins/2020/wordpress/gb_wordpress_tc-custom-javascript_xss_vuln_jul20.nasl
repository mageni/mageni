# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112797");
  script_version("2020-08-05T10:11:18+0000");
  script_tag(name:"last_modification", value:"2020-08-06 10:12:02 +0000 (Thu, 06 Aug 2020)");
  script_tag(name:"creation_date", value:"2020-08-05 10:05:00 +0000 (Wed, 05 Aug 2020)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2020-14063");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress TC Custom JavaScript Plugin < 1.2.2 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("tc-custom-javascript/detected");

  script_tag(name:"summary", value:"The WordPress plugin TC Custom JavaScript is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"insight", value:"An attacker could send a POST request to any location on a vulnerable site with the tccj-update parameter
  set to Update and the tccj-content parameter set to malicious JavaScript, and this JavaScript would display in the footer of every page on the site.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to redirect visitors to malvertising sites or steal payment information.
  Even worse, it is possible for the attacker to detect when an administrator visits the site and send a request on their behalf to infect files with a backdoor or possibly
  create a new, malicious administrator user account leading to takeover of the entire site.");

  script_tag(name:"affected", value:"WordPress TC Custom JavaScript plugin before version 1.2.2.");

  script_tag(name:"solution", value:"Update to version 1.2.2 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/tc-custom-javascript/#developers");
  script_xref(name:"URL", value:"https://www.wordfence.com/blog/2020/07/high-severity-vulnerability-patched-in-tc-custom-javascript/");

  exit(0);
}

CPE = "cpe:/a:tinycode:tc-custom-javascript";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: FALSE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "1.2.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.2.2", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );

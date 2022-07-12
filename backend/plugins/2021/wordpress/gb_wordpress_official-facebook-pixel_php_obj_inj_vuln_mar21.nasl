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

CPE = "cpe:/a:facebook:official-facebook-pixel";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112882");
  script_version("2021-04-13T13:41:23+0000");
  script_tag(name:"last_modification", value:"2021-04-14 10:27:53 +0000 (Wed, 14 Apr 2021)");
  script_tag(name:"creation_date", value:"2021-04-13 11:24:11 +0000 (Tue, 13 Apr 2021)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2021-24217");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Facebook for WordPress Plugin < 3.0.0 PHP Object Injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/official-facebook-pixel/detected");

  script_tag(name:"summary", value:"The WordPress plugin Facebook for WordPress (formerly known as Official Facebook Pixel)
  is prone to a PHP object injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The core of the PHP object injection vulnerability is within the run_action() function.
  This function is intended to deserialize user data from the event_data POST variable so that it could send the data
  to the pixel console. Unfortunately, this event_data could be supplied by a user. When user-supplied input is deserialized in PHP,
  users can supply PHP objects that can trigger magic methods and execute actions that can be used for malicious purposes.

  On its own, a deserialization vulnerability is relatively harmless, however, when combined with a gadget, or magic method,
  significant damage can be done to a site. In this case, a magic method within the plugin could be used
  to upload arbitrary files and achieve remote code execution on a vulnerable target.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to generate a PHP file in a vulnerable site's home directory.
  The PHP file contents could then be changed, allowing an attacker to achieve remote code execution.

  Note that the presence of a full POP chain also means that any other plugin with an object injection vulnerability,
  including those that do not require knowledge of the site's salts and keys, could potentially be used to achieve
  remote code execution as well if it is installed on a site with the Facebook for WordPress plugin.");

  script_tag(name:"affected", value:"WordPress Facebook for WordPress plugin before version 3.0.0.");

  script_tag(name:"solution", value:"Update to version 3.0.0 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/official-facebook-pixel/#developers");
  script_xref(name:"URL", value:"https://www.wordfence.com/blog/2021/03/two-vulnerabilities-patched-in-facebook-for-wordpress-plugin/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_is_less(version: version, test_version: "3.0.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.0.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

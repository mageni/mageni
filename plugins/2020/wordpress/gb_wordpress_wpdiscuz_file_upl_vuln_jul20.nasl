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
  script_oid("1.3.6.1.4.1.25623.1.0.112794");
  script_version("2020-07-30T09:03:59+0000");
  script_tag(name:"last_modification", value:"2020-07-31 10:00:11 +0000 (Fri, 31 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-07-30 08:47:00 +0000 (Thu, 30 Jul 2020)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress wpDiscuz Plugin 7.x < 7.0.5 Arbitrary File Upload Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wpdiscuz/detected");

  script_tag(name:"summary", value:"The WordPress plugin wpDiscuz is prone to an arbitrary file upload vulnerarbility.");

  script_tag(name:"insight", value:"The wpDiscuz comments are intended to only allow image attachments.
  However, due to the file mime type detection functions that were used, the file type verification could
  easily be bypassed, allowing unauthenticated users the ability to upload any type of file, including PHP files.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to upload arbitrary PHP files
  and then access those files to trigger their execution on the server, achieving remote code execution.

  If exploited, this vulnerability then could allow an attacker to execute commands on your server and traverse your
  hosting account to further infect any sites hosted in the account with malicious code. This would effectively
  give the attacker complete control over every site on your server.");

  script_tag(name:"affected", value:"WordPress wpDiscuz plugin version 7.0.0 through 7.0.4.");

  script_tag(name:"solution", value:"Update to version 7.0.5 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/wpdiscuz/#developers");
  script_xref(name:"URL", value:"https://www.wordfence.com/blog/2020/07/critical-arbitrary-file-upload-vulnerability-patched-in-wpdiscuz-plugin/");

  exit(0);
}

CPE = "cpe:/a:gvectors:wpdiscuz";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_in_range( version: version, test_version: "7.0.0", test_version2: "7.0.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "7.0.5", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );

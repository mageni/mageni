# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from the referenced
# advisories, and are Copyright (C) by the respective right holder(s)
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113676");
  script_version("2020-04-27T08:56:49+0000");
  script_tag(name:"last_modification", value:"2020-04-28 10:10:27 +0000 (Tue, 28 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-04-27 08:28:47 +0000 (Mon, 27 Apr 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-11928");

  script_name("WordPress Media Library Assistant Plugin < 2.82 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("media-library-assistant/detected");

  script_tag(name:"summary", value:"The WordPress plugin Media Library Assistant is prone to
  a remote code execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability can be exploited by an admin via
  the tax_query, meta_query or date_query parameter in mla_gallery.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to
  execute arbitrary code on the target machine.");

  script_tag(name:"affected", value:"WordPress Media Library Assistant plugin through version 2.81.");

  script_tag(name:"solution", value:"Update to version 2.82 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/media-library-assistant/#developers");

  exit(0);
}

CPE = "cpe:/a:media_library_assistant_project:media_library_assistant";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "2.82" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.82", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
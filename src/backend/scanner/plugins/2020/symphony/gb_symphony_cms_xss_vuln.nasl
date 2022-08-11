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

CPE = "cpe:/a:symphony-cms:symphony_cms";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108852");
  script_version("2020-08-14T13:30:00+0000");
  script_cve_id("CVE-2020-15071");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2020-08-17 09:42:20 +0000 (Mon, 17 Aug 2020)");
  script_tag(name:"creation_date", value:"2020-08-14 13:14:01 +0000 (Fri, 14 Aug 2020)");

  script_name("Symphony CMS <= 3.0.0 XSS Vulnerability");

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_symphony_cms_detect.nasl");
  script_mandatory_keys("symphony/installed");

  script_xref(name:"URL", value:"https://github.com/symphonycms/symphonycms/issues/2917");

  script_tag(name:"summary", value:"Symphony CMS is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"content/content.blueprintsevents.php in Symphony CMS allows XSS via
  fields['name'] to appendSubheading.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker
  to inject arbitrary HTML and JavaScript into the site.");

  script_tag(name:"affected", value:"Symphony CMS versions through 3.0.0.");

  script_tag(name:"solution", value:"No known solution is available as of 14th August, 2020. Information
  regarding this issue will be updated once solution details are available.");

  script_tag(name:"solution_type", value:"NoneAvailable");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less_equal( version: version, test_version: "3.0.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.0.0", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );

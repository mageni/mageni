# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.112730");
  script_version("2020-04-06T11:49:55+0000");
  script_tag(name:"last_modification", value:"2020-04-06 12:43:58 +0000 (Mon, 06 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-04-06 11:39:12 +0000 (Mon, 06 Apr 2020)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("WordPress Contavt Form 7 Datepicker Plugin <= 2.6.0 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("contact-form-7-datepicker/detected");

  script_tag(name:"summary", value:"The WordPress plugin Contact Form 7 Datepicker is prone to a stored
  cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin allows users to add a datepicker to forms generated
  by Contact Form 7, and it includes the ability to modify settings for these datepickers.
  In order to process these settings, it registered an AJAX action calling a function that failed to
  include a capability check or a nonce check");

  script_tag(name:"impact", value:"It is possible for a logged-in attacker with minimal permissions,
  such as a subscriber, to send a crafted request containing malicious JavaScript which would be stored in the plugin's settings.");

  script_tag(name:"affected", value:"WordPress plugin Contact Form 7 Datepicker through version 2.6.0.");

  script_tag(name:"solution", value:"As the Contact Form 7 Datepicker plugin is no longer being maintained, it will likely not ever be patched.
  Therefore it is recommended to deactivate and remove the plugin and search for an alternative plugin with similar functionality.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/contact-form-7-datepicker/#developers");
  script_xref(name:"URL", value:"https://www.wordfence.com/blog/2020/04/high-severity-vulnerability-leads-to-closure-of-plugin-with-over-100000-installations/");

  exit(0);
}


CPE = "cpe:/a:relu:contact-form-7-datepicker";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less_equal( version: version, test_version: "2.6.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "None", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );

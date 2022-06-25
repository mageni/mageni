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
  script_oid("1.3.6.1.4.1.25623.1.0.112815");
  script_version("2020-08-25T12:38:20+0000");
  script_tag(name:"last_modification", value:"2020-08-26 09:50:42 +0000 (Wed, 26 Aug 2020)");
  script_tag(name:"creation_date", value:"2020-08-20 11:42:00 +0000 (Thu, 20 Aug 2020)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Advanced Access Manager Plugin < 6.6.2 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/advanced-access-manager/detected");

  script_tag(name:"summary", value:"The WordPress plugin Advanced Access Manager is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"If the 'Multiple Roles Support' setting is enabled, the plugin is vulnerable to authenticated
  authorization bypass and, in some cases, privilege escalation.

  Low-privileged users could assign themselves or switch to any role with an equal or lesser user level,
  or any role that did not have an assigned user level. This could be done by sending a POST request to wp-admin/profile.php
  with typical profile update parameters and appending a aam_user_roles[] parameter set to the role they would like to use.

  The reason this worked is that the AAM_Backend_Manager::profileUpdate method that actually assigns these roles is triggered
  by the profile_update and user_register actions, and failed to use a standard capability check.


  The plugin's aam/v1/authenticate and aam/v2/authenticate REST endpoints were set to respond to a successful login with a
  json-encoded copy of all metadata about the user, potentially exposing users' information to an attacker or low-privileged user.
  This included items like the user's hashed password and their capabilities and roles, as well as any custom metadata
  that might have been added by other plugins. This might include sensitive configuration information,
  which an attacker could potentially use as part of an exploit chain.");

  script_tag(name:"impact", value:"Low-privileged attackers could potentially switch to a role that allowed them to either
  directly take over a site or could be used as part of an exploit chain, depending on which roles were configured.

  Furthermore attackers that are able to assign themselves a custom role using the vulnerability could view which capabilities
  were assigned to them, allowing them to plan the next phase of their attack.");

  script_tag(name:"affected", value:"WordPress Advanced Access Manager plugin before version 6.6.2.");

  script_tag(name:"solution", value:"Update to version 6.6.2 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/blog/2020/08/high-severity-vulnerability-patched-in-advanced-access-manager/");

  exit(0);
}

CPE = "cpe:/a:vasyltech:advanced-access-manager";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "6.6.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "6.6.2", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );

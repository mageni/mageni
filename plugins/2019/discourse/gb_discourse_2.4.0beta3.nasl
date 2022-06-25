# Copyright (C) 2019 Greenbone Networks GmbH
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

CPE = "cpe:/a:discourse:discourse";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108623");
  script_version("2019-09-18T14:07:28+0000");
  script_tag(name:"last_modification", value:"2019-09-18 14:07:28 +0000 (Wed, 18 Sep 2019)");
  script_tag(name:"creation_date", value:"2019-08-27 10:58:21 +0000 (Tue, 27 Aug 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2019-15515");

  script_name("Discourse < 2.4.0.beta3 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_discourse_detect.nasl");
  script_mandatory_keys("discourse/detected");

  script_tag(name:"summary", value:"Discourse is prone to multiple vulnerabilities including CSRF flaws.");

  script_tag(name:"insight", value:"The following flaws exist / security fixes are included:

  - Reset password when activating an account via auth provider

  - Don't send CSRF token in query string (CVE-2019-15515)

  - Bump nokogiri

  - Add rate limiting to anon JS error reporting

  - Don't reveal category details to users that do not have access

  - Restrict message-bus access on login_required sites

  - Require POST with CSRF token for OmniAuth request phase

  - Sanitize email id for use as mutex key

  - Add confirmation screen when connecting associated accounts

  - Validate backup chunk identifier.");

  script_tag(name:"affected", value:"Discourse up to and including version 2.4.0.beta2.");

  script_tag(name:"solution", value:"Update to version 2.4.0.beta3 or later.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://github.com/discourse/discourse/pull/8026");
  script_xref(name:"URL", value:"https://meta.discourse.org/t/discourse-2-4-0-beta3-release-notes/127600");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];

if (version_is_less(version: vers, test_version: "2.4.0") ||
    version_in_range(version: vers, test_version: "2.4.0.beta1", test_version2: "2.4.0.beta2")) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.4.0.beta3", install_path:infos["location"] );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

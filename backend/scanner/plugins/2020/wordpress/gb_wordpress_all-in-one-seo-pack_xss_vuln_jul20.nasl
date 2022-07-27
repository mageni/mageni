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
  script_oid("1.3.6.1.4.1.25623.1.0.112796");
  script_version("2020-08-04T10:10:37+0000");
  script_tag(name:"last_modification", value:"2020-08-05 10:06:21 +0000 (Wed, 05 Aug 2020)");
  script_tag(name:"creation_date", value:"2020-08-04 09:11:00 +0000 (Tue, 04 Aug 2020)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress All in One SEO Pack Plugin < 3.6.2 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("all-in-one-seo-pack/detected");

  script_tag(name:"summary", value:"The WordPress plugin All in One SEO Pack is prone to a stored cross-site scripting (XSS) vulnerarbility.");

  script_tag(name:"insight", value:"The SEO meta data for posts, including the SEO title and SEO description fields,
  had no input sanitization allowing lower-level users like contributors and authors the ability to inject HTML and malicious JavaScript into those fields.");

  script_tag(name:"impact", value:"If the malicious JavaScript was executed in an Administrator's browser,
  it could be used to inject backdoors or add new administrative users and take over a site.");

  script_tag(name:"affected", value:"WordPress All in One SEO Pack plugin before version 3.6.2.");

  script_tag(name:"solution", value:"Update to version 3.6.2 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/all-in-one-seo-pack/#developers");
  script_xref(name:"URL", value:"https://www.wordfence.com/blog/2020/07/2-million-users-affected-by-vulnerability-in-all-in-one-seo-pack/");

  exit(0);
}

CPE = "cpe:/a:semperplugins:all-in-one-seo-pack";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: FALSE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

# nb: All versions before 2.2.7.3 had "Stable tag: trunk".
# In case the plugin has been located, it can still be reported as vulnerable
if( location && ! version ) {
  report = report_fixed_ver( installed_version: "< 2.2.7.3", fixed_version: "3.6.2", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_is_less( version: version, test_version: "3.6.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.6.2", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );

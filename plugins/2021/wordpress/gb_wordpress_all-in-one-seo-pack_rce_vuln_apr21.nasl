# Copyright (C) 2021 Greenbone Networks GmbH
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

CPE = "cpe:/a:semperplugins:all-in-one-seo-pack";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146187");
  script_version("2021-06-29T08:19:26+0000");
  script_tag(name:"last_modification", value:"2021-06-29 10:13:44 +0000 (Tue, 29 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-06-29 08:01:57 +0000 (Tue, 29 Jun 2021)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2021-24307");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress All in One SEO Pack Plugin < 4.1.0.2 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/all-in-one-seo-pack/detected");

  script_tag(name:"summary", value:"The WordPress plugin All in One SEO Pack is prone to a remote
  code execution (RCE) vulnerability.");

  script_tag(name:"insight", value:"The All in One SEO - Best WordPress SEO Plugin enables
  authenticated users with 'aioseo_tools_settings' privilege (most of the time admin) to execute
  arbitrary code on the underlying host. Users can restore plugin's configuration by uploading a
  backup .ini file in the section 'Tool > Import/Export'. However, the plugin attempts to
  unserialize values of the .ini file. Moreover, the plugin embeds Monolog library which can be
  used to craft a gadget chain and thus trigger system command execution.");

  script_tag(name:"impact", value:"An authenticated attacker might execute arbitrary code.");

  script_tag(name:"affected", value:"WordPress All in One SEO Pack plugin prior to version 4.1.0.2.");

  script_tag(name:"solution", value:"Update to version 4.1.0.2 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/all-in-one-seo-pack/#developers");
  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/ab2c94d2-f6c4-418b-bd14-711ed164bcf1");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: FALSE))
  exit(0);

version = infos["version"];
location = infos["location"];

# nb: All versions before 2.2.7.3 had "Stable tag: trunk".
# In case the plugin has been located, it can still be reported as vulnerable
if (location && !version) {
  report = report_fixed_ver(installed_version: "< 2.2.7.3", fixed_version: "4.1.0.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
} else if (version_is_less(version: version, test_version: "4.1.0.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.1.0.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

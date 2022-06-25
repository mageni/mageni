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

CPE = "cpe:/a:sensiolabs:symfony";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.144528");
  script_version("2020-09-07T09:43:22+0000");
  script_tag(name:"last_modification", value:"2020-09-08 09:56:35 +0000 (Tue, 08 Sep 2020)");
  script_tag(name:"creation_date", value:"2020-09-07 05:17:20 +0000 (Mon, 07 Sep 2020)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner_unreliable"); # Patches are available

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-15094");

  script_name("Symfony 4.3.0 - 4.4.12, 5.0.0 - 5.1.4 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_symfony_consolidation.nasl");
  script_mandatory_keys("symfony/detected");

  script_tag(name:"summary", value:"Symfony is prone to a remote code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The CachingHttpClient class from the HttpClient Symfony component relies on
  the HttpCache class to handle requests. HttpCache uses internal headers like X-Body-Eval and X-Body-File to
  control the restoration of cached responses. The class was initially written with surrogate caching and ESI
  support in mind (all HTTP calls come from a trusted backend in that scenario). But when used by CachingHttpClient
  and if an attacker can control the response for a request being made by the CachingHttpClient, remote code
  execution is possible.");

  script_tag(name:"affected", value:"Symfony versions 4.3.0 to 4.4.12 and 5.0.0 to 5.1.4.");

  script_tag(name:"solution", value:"Update to version 4.4.13, 5.1.5 or later.");

  script_xref(name:"URL", value:"https://symfony.com/blog/cve-2020-15094-prevent-rce-when-calling-untrusted-remote-with-cachinghttpclient");
  script_xref(name:"URL", value:"https://github.com/symfony/symfony/security/advisories/GHSA-754h-5r27-7x3r");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "4.3.0", test_version2: "4.4.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.4.13", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.0.0", test_version2: "5.1.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.1.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

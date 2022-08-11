# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112506");
  script_version("2019-04-03T09:59:09+0000");
  script_tag(name:"last_modification", value:"2019-04-03 09:59:09 +0000 (Wed, 03 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-02-05 11:16:13 +0100 (Tue, 05 Feb 2019)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2019-7325", "CVE-2019-7326", "CVE-2019-7327", "CVE-2019-7328", "CVE-2019-7329",
  "CVE-2019-7330", "CVE-2019-7331", "CVE-2019-7332", "CVE-2019-7333", "CVE-2019-7334", "CVE-2019-7335",
  "CVE-2019-7336", "CVE-2019-7337", "CVE-2019-7338", "CVE-2019-7339", "CVE-2019-7340", "CVE-2019-7341",
  "CVE-2019-7342", "CVE-2019-7343", "CVE-2019-7344", "CVE-2019-7345", "CVE-2019-7346", "CVE-2019-7347",
  "CVE-2019-7348", "CVE-2019-7349", "CVE-2019-7350", "CVE-2019-7351", "CVE-2019-7352");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("ZoneMinder <= 1.33.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_zoneminder_detect.nasl");
  script_mandatory_keys("zoneminder/installed");

  script_tag(name:"summary", value:"ZoneMinder is prone to multiple vulnerabilities.");
  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Multiple self-stored, reflected and POST cross-site scripting (XSS) vulnerabilities.

  - Session fixation.

  - Cross-site request forgery.

  - Log injection.

  - A Time-of-check Time-of-use (TOCTOU) race condition.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to execute
  HTML or JavaScript code via multiple parameters, to access and modify records (add/delete Monitors, Users, etc.),
  to inject log messages, to hijack another user's account or to have other unspecified impact on the application and its host system.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"No known solution is available as of 03rd April, 2019.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://github.com/ZoneMinder/zoneminder/issues/2447");
  script_xref(name:"URL", value:"https://github.com/ZoneMinder/zoneminder/issues/2452");
  script_xref(name:"URL", value:"https://github.com/ZoneMinder/zoneminder/issues/2446");
  script_xref(name:"URL", value:"https://github.com/ZoneMinder/zoneminder/issues/2449");
  script_xref(name:"URL", value:"https://github.com/ZoneMinder/zoneminder/issues/2451");
  script_xref(name:"URL", value:"https://github.com/ZoneMinder/zoneminder/issues/2448");
  script_xref(name:"URL", value:"https://github.com/ZoneMinder/zoneminder/issues/2441");
  script_xref(name:"URL", value:"https://github.com/ZoneMinder/zoneminder/issues/2442");
  script_xref(name:"URL", value:"https://github.com/ZoneMinder/zoneminder/issues/2453");
  script_xref(name:"URL", value:"https://github.com/ZoneMinder/zoneminder/issues/2443");
  script_xref(name:"URL", value:"https://github.com/ZoneMinder/zoneminder/issues/2457");
  script_xref(name:"URL", value:"https://github.com/ZoneMinder/zoneminder/issues/2456");
  script_xref(name:"URL", value:"https://github.com/ZoneMinder/zoneminder/issues/2460");
  script_xref(name:"URL", value:"https://github.com/ZoneMinder/zoneminder/issues/2454");
  script_xref(name:"URL", value:"https://github.com/ZoneMinder/zoneminder/issues/2463");
  script_xref(name:"URL", value:"https://github.com/ZoneMinder/zoneminder/issues/2462");
  script_xref(name:"URL", value:"https://github.com/ZoneMinder/zoneminder/issues/2464");
  script_xref(name:"URL", value:"https://github.com/ZoneMinder/zoneminder/issues/2461");
  script_xref(name:"URL", value:"https://github.com/ZoneMinder/zoneminder/issues/2468");
  script_xref(name:"URL", value:"https://github.com/ZoneMinder/zoneminder/issues/2455");
  script_xref(name:"URL", value:"https://github.com/ZoneMinder/zoneminder/issues/2476");
  script_xref(name:"URL", value:"https://github.com/ZoneMinder/zoneminder/issues/2469");
  script_xref(name:"URL", value:"https://github.com/ZoneMinder/zoneminder/issues/2465");
  script_xref(name:"URL", value:"https://github.com/ZoneMinder/zoneminder/issues/2467");
  script_xref(name:"URL", value:"https://github.com/ZoneMinder/zoneminder/issues/2466");
  script_xref(name:"URL", value:"https://github.com/ZoneMinder/zoneminder/issues/2471");
  script_xref(name:"URL", value:"https://github.com/ZoneMinder/zoneminder/issues/2475");
  script_xref(name:"URL", value:"https://github.com/ZoneMinder/zoneminder/issues/2450");
  script_xref(name:"URL", value:"https://github.com/ZoneMinder/zoneminder/commit/b2a97ee190c6dc3e30b9c36b9c33c33348dde4d6");

  exit(0);
}

CPE = "cpe:/a:zoneminder:zoneminder";

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if(version_is_less_equal(version: version, test_version: "1.33.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None Available");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

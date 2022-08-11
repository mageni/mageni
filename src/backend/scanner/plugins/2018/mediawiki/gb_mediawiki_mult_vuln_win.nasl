##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mediawiki_mult_vuln_win.nasl 12590 2018-11-30 07:32:04Z asteins $
#
# MediaWiki Multiple Vulnerabilities Sept18 (Windows)
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
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
###############################################################################

CPE = "cpe:/a:mediawiki:mediawiki";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141565");
  script_version("$Revision: 12590 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-30 08:32:04 +0100 (Fri, 30 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-10-05 10:13:36 +0700 (Fri, 05 Oct 2018)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");

  script_cve_id("CVE-2018-0503", "CVE-2018-0504", "CVE-2018-0505");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MediaWiki Multiple Vulnerabilities Sept18 (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_mediawiki_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mediawiki/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"MediaWiki is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"MediaWiki is prone to multiple vulnerabilities:

  - $wgRateLimits entry for 'user' overrides 'newbie' (CVE-2018-0503)

  - Redirect/logid can link to the incorrect log and reveal hidden information (CVE-2018-0504)

  - BotPasswords can bypass CentralAuth's account lock (CVE-2018-0505)");

  script_tag(name:"affected", value:"MediaWiki 1.27.x, 1.29.x, 1.30.x, 1.31.x and prior.");

  script_tag(name:"solution", value:"Update to version 1.27.5, 1.29.3, 1.30.1, 1.31.1 or later.");

  script_xref(name:"URL", value:"https://lists.wikimedia.org/pipermail/wikitech-l/2018-September/090849.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "1.27.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.27.5");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "1.28", test_version2: "1.29.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.29.3");
  security_message(port: port, data: report);
  exit(0);
}

if (version =~ "^1\.30\.0") {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.30.1");
  security_message(port: port, data: report);
  exit(0);
}

if (version =~ "^1\.31\.0") {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.31.1");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);

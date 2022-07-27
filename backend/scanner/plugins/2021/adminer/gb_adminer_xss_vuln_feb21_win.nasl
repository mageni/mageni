# Copyright (C) 2021 Greenbone Networks GmbH
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

CPE = "cpe:/a:adminer:adminer";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145371");
  script_version("2021-02-12T09:03:06+0000");
  script_tag(name:"last_modification", value:"2021-02-12 11:04:26 +0000 (Fri, 12 Feb 2021)");
  script_tag(name:"creation_date", value:"2021-02-12 04:14:20 +0000 (Fri, 12 Feb 2021)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2020-35572");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Adminer 4.7.0 < 4.7.9 XSS Vulnerability (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_adminer_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("adminer/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Adminer is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Adminer allows XSS via the history parameter to the default URI.");

  script_tag(name:"affected", value:"Adminer versions 4.7.0 through 4.7.8.");

  script_tag(name:"solution", value:"Update to version 4.7.9 or later.");

  script_xref(name:"URL", value:"https://github.com/vrana/adminer/security/advisories/GHSA-9pgx-gcph-mpqr");
  script_xref(name:"URL", value:"https://sourceforge.net/p/adminer/bugs-and-features/775/");
  script_xref(name:"URL", value:"https://sourceforge.net/p/adminer/news/2021/02/adminer-479-released/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version:"4.7.0", test_version2: "4.7.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.7.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

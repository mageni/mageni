# Copyright (C) 2022 Greenbone Networks GmbH
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

CPE = "cpe:/a:artifex:ghostscript";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147696");
  script_version("2022-02-24T04:40:41+0000");
  script_tag(name:"last_modification", value:"2022-02-24 04:40:41 +0000 (Thu, 24 Feb 2022)");
  script_tag(name:"creation_date", value:"2022-02-24 04:24:55 +0000 (Thu, 24 Feb 2022)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");

  script_cve_id("CVE-2021-3781");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Ghostscript 9.50 < 9.55.0 Sandbox Escape Vulnerability - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_ghostscript_detect_lin.nasl");
  script_mandatory_keys("artifex/ghostscript/lin/detected");

  script_tag(name:"summary", value:"Ghostscript is prone to a sandbox escape vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The file access protection built into Ghostscript proved
  insufficient for the '%pipe%' PostScript device, when combined with Ghostscript's requirement to
  be able to create and control temporary files in the conventional temporary file directories (for
  example, '/tmp' or '/temp').");

  script_tag(name:"affected", value:"Ghostscript version 9.50 through 9.54.x.");

  script_tag(name:"solution", value:"Update to version 9.55 or later.");

  script_xref(name:"URL", value:"https://ghostscript.com/blog/CVE-2021-3781.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range_exclusive(version: version, test_version_lo: "9.50", test_version_up: "9.55")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.55", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);

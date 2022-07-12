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

CPE = "cpe:/o:greenbone:greenbone_os";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142852");
  script_version("2019-09-06T06:52:28+0000");
  script_tag(name:"last_modification", value:"2019-09-06 06:52:28 +0000 (Fri, 06 Sep 2019)");
  script_tag(name:"creation_date", value:"2019-09-06 02:27:18 +0000 (Fri, 06 Sep 2019)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Greenbone OS 5.0.x < 5.0.10 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_greenbone_os_detect.nasl");
  script_mandatory_keys("greenbone/gos/detected", "greenbone/gsm/type");

  script_tag(name:"summary", value:"Greenbone OS is prone to a reflected cross-site scripting vulnerability in
  the Greenbone Security Assistant (GSA) web user interface.");

  script_tag(name:"affected", value:"All GSM models except GSM 25, GSM 25V and GSM 35 running Greenbone OS 5.0.x
  prior to version 5.0.10.");

  script_tag(name:"solution", value:"Update to version 5.0.10 or later.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://github.com/greenbone/gsa/issues/1601");
  script_xref(name:"URL", value:"https://www.greenbone.net/en/roadmap-lifecycle/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!type = get_kb_item("greenbone/gsm/type"))
  exit(0);

if (type =~ "^(25|25V|35)$")
  exit(99);

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

version = str_replace(string: version, find: "-", replace: ".");

if (version_in_range(version: version, test_version: "5.0", test_version2: "5.0.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.10");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);

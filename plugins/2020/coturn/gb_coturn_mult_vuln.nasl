# Copyright (C) 2020 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of the respective author(s)
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

CPE = "cpe:/a:coturn:coturn";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143561");
  script_version("2020-02-27T06:44:21+0000");
  script_tag(name:"last_modification", value:"2020-02-27 11:18:00 +0000 (Thu, 27 Feb 2020)");
  script_tag(name:"creation_date", value:"2020-02-27 06:40:41 +0000 (Thu, 27 Feb 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2020-6061", "CVE-2020-6062");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("coturn <= 4.5.1.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_coturn_http_detect.nasl");
  script_mandatory_keys("coturn/detected");

  script_tag(name:"summary", value:"coturn is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"coturn is prone to multiple vulnerabilities:

  - Heap overflow vulnerability (CVE-2020-6061)

  - DoS vulnerability (CVE-2020-6062)");

  script_tag(name:"affected", value:"coturn version 4.5.1.1 and probably prior.");

  script_tag(name:"solution", value:"No known solution is available as of 27th February, 2020.
  Information regarding this issue will be updated once solution details are available.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://talosintelligence.com/vulnerability_reports/TALOS-2020-0984");
  script_xref(name:"URL", value:"https://talosintelligence.com/vulnerability_reports/TALOS-2020-0985");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less_equal(version: version, test_version: "4.5.1.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None");
  security_message(port: 0, data: report);
  exit(0);
}

exit(0);

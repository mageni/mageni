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

CPE_PREFIX = "cpe:/h:qnap";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117291");
  script_version("2021-04-07T09:01:03+0000");
  script_tag(name:"last_modification", value:"2021-04-07 10:26:17 +0000 (Wed, 07 Apr 2021)");
  script_tag(name:"creation_date", value:"2021-04-07 08:45:48 +0000 (Wed, 07 Apr 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2020-2509", "CVE-2020-9490");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS < 4.3.6.1620 Build 20210322 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_qnap_nas_detect.nasl");
  script_mandatory_keys("qnap/qts");

  script_tag(name:"summary", value:"QNAP QTS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2020-2509: command injection vulnerability

  - CVE-2020-9490: a vulnerability in Apache HTTP server");

  script_tag(name:"affected", value:"QNAP QTS prior to version 4.3.6.1620 Build 20210322.");

  script_tag(name:"solution", value:"Update to version 4.3.6.1620 Build 20210322 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/de-de/release-notes/qts/4.3.6.1620/20210322");
  script_xref(name:"URL", value:"https://securingsam.com/new-vulnerabilities-allow-complete-takeover/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX))
  exit(0);

CPE = infos["cpe"];

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "4.3.6_20210322")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.6_20210322");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);

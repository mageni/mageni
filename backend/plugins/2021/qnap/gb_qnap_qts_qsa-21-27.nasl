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
  script_oid("1.3.6.1.4.1.25623.1.0.146152");
  script_version("2021-06-18T08:20:05+0000");
  script_tag(name:"last_modification", value:"2021-06-18 10:19:50 +0000 (Fri, 18 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-06-18 08:07:52 +0000 (Fri, 18 Jun 2021)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");

  script_cve_id("CVE-2021-20254");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS SMB Vulnerability (QSA-21-27)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_qnap_nas_detect.nasl");
  script_mandatory_keys("qnap/qts");

  script_tag(name:"summary", value:"QNAP QTS is prone to an SMB out-of-bounds read vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An SMB out-of-bounds read vulnerability has been reported to
  affect QNAP NAS running QTS. If exploited, this vulnerability allows attackers to obtain
  sensitive information on the system.");

  script_tag(name:"affected", value:"QNAP NAS QTS prior version 4.5.3.1670 Build 20210515.");

  script_tag(name:"solution", value:"Update to version 4.5.3.1670 Build 20210515 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/QSA-21-27");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX))
  exit(0);

CPE = infos["cpe"];

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "4.5.3_20210515")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.5.3_20210515");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);

# Copyright (C) 2020 Greenbone Networks GmbH
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

CPE = "cpe:/o:d-link:dap-1522_firmware";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144348");
  script_version("2020-08-04T05:31:14+0000");
  script_tag(name:"last_modification", value:"2020-08-04 10:39:08 +0000 (Tue, 04 Aug 2020)");
  script_tag(name:"creation_date", value:"2020-08-04 03:28:03 +0000 (Tue, 04 Aug 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2020-15896");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("D-Link DAP-1522 <= 1.42 Authentication Bypass Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dap_detect.nasl");
  script_mandatory_keys("Host/is_dlink_dap_device");

  script_tag(name:"summary", value:"D-Link DAP-1522 is prone to an authentication bypass vulnerability.");

  script_tag(name:"insight", value:"There exist a few pages that are directly accessible by any unauthorized user,
  e.g., logout.php and login.php. This occurs because of checking the value of NO_NEED_AUTH. If the value of
  NO_NEED_AUTH is 1, the user has direct access to the webpage without any authentication. By appending a query
  string NO_NEED_AUTH with the value of 1 to any protected URL, any unauthorized user can access the application
  directly, as demonstrated by bsc_lan.php?NO_NEED_AUTH=1.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"D-Link DAP-1522 version 1.42 and prior.");

  script_tag(name:"solution", value:"No solution was made available by the vendor. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by another one.
  The vendor states: DAP-1522 (EOS: 07/01/2016) have reached its End-of-Support ('EOS') / End-of-Life ('EOL') Date.
  As a general policy, when the product reaches EOS/EOL, it can no longer be supported, and all firmware
  development for the product ceases, except in certain unique situations.");

  script_xref(name:"URL", value:"https://supportannouncement.us.dlink.com/announcement/publication.aspx?name=SAP10169");
  script_xref(name:"URL", value:"https://research.loginsoft.com/vulnerability/authentication-bypass-in-d-link-firmware-dap-1522/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less_equal(version: version, test_version: "1.42")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None");
  security_message(port: 0, data: report);
  exit(0);
}

exit(0);

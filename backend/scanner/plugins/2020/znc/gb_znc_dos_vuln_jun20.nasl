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

CPE = "cpe:/a:znc:znc";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144112");
  script_version("2020-06-16T05:29:19+0000");
  script_tag(name:"last_modification", value:"2020-06-17 08:59:13 +0000 (Wed, 17 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-06-16 05:16:42 +0000 (Tue, 16 Jun 2020)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2020-13775");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ZNC < 1.8.1 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_znc_consolidation.nasl");
  script_mandatory_keys("znc/detected");

  script_tag(name:"summary", value:"ZNC is prone to a denial of service vulnerability.");

  script_tag(name:"insight", value:"ZNC allows authenticated users to trigger an application crash (with a NULL
  pointer dereference) if echo-message is not enabled and there is no network.");

  script_tag(name:"affected", value:"ZNC version 1.8.0 and prior.");

  script_tag(name:"solution", value:"Update to version 1.8.1 or later.");

  script_xref(name:"URL", value:"https://github.com/znc/znc/releases/tag/znc-1.8.1");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "1.8.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.8.1");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);

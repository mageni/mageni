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

CPE = "cpe:/h:hp:officejet_7110_wide_format_eprinter";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147072");
  script_version("2021-11-02T09:50:03+0000");
  script_tag(name:"last_modification", value:"2021-11-02 09:50:03 +0000 (Tue, 02 Nov 2021)");
  script_tag(name:"creation_date", value:"2021-11-02 09:27:41 +0000 (Tue, 02 Nov 2021)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:M/C:P/I:P/A:P");

  script_cve_id("CVE-2021-3441");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("HP OfficeJet 7110 XSS Vulnerability (HPSBPI03742)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_hp_printer_detect.nasl");
  script_mandatory_keys("hp_printer/installed");

  script_tag(name:"summary", value:"HP OfficeJet 7110 Wide Format ePrinter is prone to a cross-site
  scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"HP OfficeJet 7110 Wide Format ePrinter prior to version 2117A.");

  script_tag(name:"solution", value:"Update to version 2117A or later.");

  script_xref(name:"URL", value:"https://support.hp.com/us-en/document/ish_4433829-4433857-16/hpsbpi03742");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (revcomp(a: version, b: "EIP2FN2117A") < 0) {
  report = report_fixed_ver(installed_version: version, fixed_version: "EIP2FN2117A");
  security_message(port: 0, data: report);
  exit(0);
}

exit(0);

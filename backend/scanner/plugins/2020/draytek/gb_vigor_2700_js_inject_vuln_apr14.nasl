# Copyright (C) 2020 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108736");
  script_version("2020-04-03T12:56:51+0000");
  script_tag(name:"last_modification", value:"2020-04-06 12:43:58 +0000 (Mon, 06 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-04-03 11:41:58 +0000 (Fri, 03 Apr 2020)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2013-5703");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("DrayTek Vigor2700 Series < 2.8.4 Javascript Injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_draytek_vigor_consolidation.nasl");
  script_mandatory_keys("draytek/vigor/detected");

  script_tag(name:"summary", value:"Multiple DrayTek Vigor Routers are prone to a javascript injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple DrayTek Vigor Routers allowing remote attackers to execute arbitrary
  JavaScript code, and modify settings or the DNS cache, via a crafted SSID value that is not properly handled during
  insertion into the sWlessSurvey value in variables.js.");

  script_tag(name:"affected", value:"DrayTek Vigor2700, Vigor2700G, Vigor2700V and Vigor2700VG prior to version 2.8.4.");

  script_tag(name:"solution", value:"Update to version 2.8.4 or later.");

  script_xref(name:"URL", value:"https://www.kb.cert.org/vuls/id/101462/");
  script_xref(name:"URL", value:"https://www.draytek.co.uk/support/downloads/legacy-products/legacy-router/vigor-2700/send/396-vigor-2700/744-readme-v2700");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:draytek:vigor2700_firmware",
                     "cpe:/o:draytek:vigor2700g_firmware",
                     "cpe:/o:draytek:vigor2700v_firmware",
                     "cpe:/o:draytek:vigor2700vg_firmware");

if (!version = get_app_version(cpe: cpe_list, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "2.8.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.8.4");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);

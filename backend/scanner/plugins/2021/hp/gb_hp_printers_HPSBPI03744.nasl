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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147114");
  script_version("2021-11-08T14:03:29+0000");
  script_tag(name:"last_modification", value:"2021-11-08 14:03:29 +0000 (Mon, 08 Nov 2021)");
  script_tag(name:"creation_date", value:"2021-11-05 07:42:34 +0000 (Fri, 05 Nov 2021)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-04 18:33:00 +0000 (Thu, 04 Nov 2021)");

  script_cve_id("CVE-2021-3662");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("HP Printer XSS Vulnerability (HPSBPI03744)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_hp_printer_detect.nasl");
  script_mandatory_keys("hp_printer/installed");

  script_tag(name:"summary", value:"Multiple HP printer are prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Certain HP Enterprise LaserJet and PageWide MFPs may be
  vulnerable to a stored XSS.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://support.hp.com/us-en/document/ish_4577473-4577502-16/hpsbpi03744");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/h:hp:color_laserjet_mfp_m578",
                     "cpe:/h:hp:color_laserjet_flow_mfp_m578",
                     "cpe:/h:hp:color_laserjet_mfp_m880",
                     "cpe:/h:hp:color_laserjet_flow_mfp_m880",
                     "cpe:/h:hp:color_laserjet_mfp_m577",
                     "cpe:/h:hp:color_laserjet_flow_mfp_m577",
                     "cpe:/h:hp:color_laserjet_mfp_m680",
                     "cpe:/h:hp:color_laserjet_flow_mfp_m680",
                     "cpe:/h:hp:color_laserjet_mfp_m681",
                     "cpe:/h:hp:color_laserjet_flow_mfp_m681",
                     "cpe:/h:hp:color_laserjet_mfp_m682",
                     "cpe:/h:hp:color_laserjet_flow_mfp_m682",
                     "cpe:/h:hp:color_laserjet_mfp_m776",
                     "cpe:/h:hp:color_laserjet_flow_mfp_m776",
                     "cpe:/h:hp:color_laserjet_mfp_m577",
                     "cpe:/h:hp:color_laserjet_flow_mfp_m577",
                     "cpe:/h:hp:laserjet_500_color_mfp_m575",
                     "cpe:/h:hp:laserjet_500_color_flow_mfp_m575",
                     "cpe:/h:hp:laserjet_500_mfp_m525",
                     "cpe:/h:hp:laserjet_500_flow_mfp_m525",
                     "cpe:/h:hp:laserjet_700_color_mfp_m775",
                     "cpe:/h:hp:laserjet_flow_mfp_m830",
                     "cpe:/h:hp:laserjet_mfp_m527",
                     "cpe:/h:hp:laserjet_flow_mfp_m527",
                     "cpe:/h:hp:laserjet_mfp_m528",
                     "cpe:/h:hp:laserjet_mfp_m630",
                     "cpe:/h:hp:laserjet_flow_mfp_m630",
                     "cpe:/h:hp:laserjet_mfp_m631",
                     "cpe:/h:hp:laserjet_flow_mfp_m631",
                     "cpe:/h:hp:laserjet_mfp_m632",
                     "cpe:/h:hp:laserjet_flow_mfp_m632",
                     "cpe:/h:hp:laserjet_mfp_m633",
                     "cpe:/h:hp:laserjet_flow_mfp_m633",
                     "cpe:/h:hp:laserjet_mfp_m634",
                     "cpe:/h:hp:laserjet_flow_mfp_m634",
                     "cpe:/h:hp:laserjet_mfp_m635",
                     "cpe:/h:hp:laserjet_flow_mfp_m635",
                     "cpe:/h:hp:laserjet_mfp_m636",
                     "cpe:/h:hp:laserjet_flow_mfp_m636",
                     "cpe:/h:hp:laserjet_mfp_m725",
                     "cpe:/h:hp:officejet_color_mfp_x585",
                     "cpe:/h:hp:pagewide_color_mfp_774",
                     "cpe:/h:hp:pagewide_color_mfp_779",
                     "cpe:/h:hp:pagewide_color_mfp_785",
                     "cpe:/h:hp:pagewide_color_mfp_586",
                     "cpe:/h:hp:pagewide_color_flow_mfp_586",
                     "cpe:/h:hp:pagewide_color_mfp_780",
                     "cpe:/h:hp:pagewide_color_flow_mfp_780",
                     "cpe:/h:hp:color_laserjet_mfp_e57540",
                     "cpe:/h:hp:color_laserjet_flow_mfp_e57540",
                     "cpe:/h:hp:color_laserjet_mfp_e67550",
                     "cpe:/h:hp:color_laserjet_flow_mfp_e67550",
                     "cpe:/h:hp:color_laserjet_mfp_e67560",
                     "cpe:/h:hp:color_laserjet_flow_mfp_e67560",
                     "cpe:/h:hp:color_laserjet_mfp_e67650",
                     "cpe:/h:hp:color_laserjet_mfp_e67660",
                     "cpe:/h:hp:color_laserjet_mfp_e77422",
                     "cpe:/h:hp:color_laserjet_mfp_e77423",
                     "cpe:/h:hp:color_laserjet_mfp_e77424",
                     "cpe:/h:hp:color_laserjet_mfp_e77425",
                     "cpe:/h:hp:color_laserjet_mfp_e77426",
                     "cpe:/h:hp:color_laserjet_mfp_e77427",
                     "cpe:/h:hp:color_laserjet_mfp_e77428",
                     "cpe:/h:hp:color_laserjet_mfp_e77822",
                     "cpe:/h:hp:color_laserjet_flow_mfp_e77822",
                     "cpe:/h:hp:color_laserjet_mfp_e77825",
                     "cpe:/h:hp:color_laserjet_flow_mfp_e77825",
                     "cpe:/h:hp:color_laserjet_mfp_e77830",
                     "cpe:/h:hp:color_laserjet_flow_mfp_e77830",
                     "cpe:/h:hp:color_laserjet_mfp_e78223",
                     "cpe:/h:hp:color_laserjet_mfp_e78224",
                     "cpe:/h:hp:color_laserjet_mfp_e78225",
                     "cpe:/h:hp:color_laserjet_mfp_e78226",
                     "cpe:/h:hp:color_laserjet_mfp_e78227",
                     "cpe:/h:hp:color_laserjet_mfp_e78228",
                     "cpe:/h:hp:color_laserjet_mfp_e78323",
                     "cpe:/h:hp:color_laserjet_mfp_e78330",
                     "cpe:/h:hp:color_laserjet_mfp_e87640",
                     "cpe:/h:hp:color_laserjet_flow_mfp_e87640",
                     "cpe:/h:hp:color_laserjet_mfp_e87650",
                     "cpe:/h:hp:color_laserjet_flow_mfp_e87650",
                     "cpe:/h:hp:color_laserjet_mfp_e87660",
                     "cpe:/h:hp:color_laserjet_flow_mfp_e87660",
                     "cpe:/h:hp:laserjet_mfp_e52545",
                     "cpe:/h:hp:laserjet_flow_mfp_e52545",
                     "cpe:/h:hp:laserjet_mfp_e52546",
                     "cpe:/h:hp:laserjet_mfp_e62555",
                     "cpe:/h:hp:laserjet_flow_mfp_e62555",
                     "cpe:/h:hp:laserjet_mfp_e62565",
                     "cpe:/h:hp:laserjet_flow_mfp_e62565",
                     "cpe:/h:hp:laserjet_flow_mfp_e62575",
                     "cpe:/h:hp:laserjet_mfp_e62655",
                     "cpe:/h:hp:laserjet_mfp_e62665",
                     "cpe:/h:hp:laserjet_flow_mfp_e62675",
                     "cpe:/h:hp:laserjet_mfp_e72425",
                     "cpe:/h:hp:laserjet_mfp_e72430",
                     "cpe:/h:hp:laserjet_mfp_e72525",
                     "cpe:/h:hp:laserjet_flow_mfp_e72525",
                     "cpe:/h:hp:laserjet_mfp_e72530",
                     "cpe:/h:hp:laserjet_flow_mfp_e72530",
                     "cpe:/h:hp:laserjet_mfp_e72535",
                     "cpe:/h:hp:laserjet_flow_mfp_e72535",
                     "cpe:/h:hp:laserjet_mfp_e82540",
                     "cpe:/h:hp:laserjet_flow_mfp_e82540",
                     "cpe:/h:hp:laserjet_mfp_e82550",
                     "cpe:/h:hp:laserjet_flow_mfp_e82550",
                     "cpe:/h:hp:laserjet_mfp_e82560",
                     "cpe:/h:hp:laserjet_flow_mfp_e82560",
                     "cpe:/h:hp:pagewide_color_mfp_e58650",
                     "cpe:/h:hp:pagewide_color_flow_mfp_e58650",
                     "cpe:/h:hp:pagewide_color_mfp_e77650",
                     "cpe:/h:hp:pagewide_color_flow_mfp_e77650",
                     "cpe:/h:hp:pagewide_color_flow_mfp_e77650",
                     "cpe:/h:hp:pagewide_color_mfp_p77440",
                     "cpe:/h:hp:pagewide_color_mfp_p77940",
                     "cpe:/h:hp:pagewide_color_mfp_p77950",
                     "cpe:/h:hp:pagewide_color_mfp_p77960");

if (!infos = get_app_port_from_list(cpe_list: cpe_list))
  exit(0);

cpe = infos["cpe"];

if (!version = get_app_version(cpe: cpe, nofork: TRUE))
  exit(0);

if (cpe =~ "^cpe:/h:hp:color_laserjet_(flow_)?mfp_m880" ||
    cpe =~ "^cpe:/h:hp:color_laserjet_(flow_)?mfp_m680" ||
    cpe =~ "^cpe:/h:hp:laserjet_500_color_(flow_)?mfp_m575" ||
    cpe =~ "^cpe:/h:hp:laserjet_500_(flow_)?mfp_m525" ||
    cpe == "cpe:/h:hp:laserjet_700_color_mfp_m775" ||
    cpe == "cpe:/h:hp:laserjet_flow_mfp_m830" ||
    cpe =~ "^cpe:/h:hp:laserjet_(flow_)?mfp_m630" ||
    cpe == "cpe:/h:hp:laserjet_mfp_m725" ||
    cpe == "cpe:/h:hp:officejet_color_mfp_x585") {
  if (version_is_less(version: version, test_version: "4.11.2.1")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "4.11.2.1");
    security_message(port: 0, data: report);
    exit(0);
  }
} else {
  if (version_is_less(version: version, test_version: "4.11.2.1")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "4.11.2.1");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version =~ "^5\." && version_is_less(version: version, test_version: "5.3")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "5.3");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);

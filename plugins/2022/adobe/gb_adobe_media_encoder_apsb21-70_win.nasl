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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA

CPE = "cpe:/a:adobe:media_encoder";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.821120");
  script_version("2022-06-15T14:04:03+0000");
  script_cve_id("CVE-2021-36070", "CVE-2021-46818", "CVE-2021-46817");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-06-15 14:04:03 +0000 (Wed, 15 Jun 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-09 14:10:00 +0000 (Thu, 09 Sep 2021)");
  script_tag(name:"creation_date", value:"2022-06-15 16:49:00 +0530 (Wed, 15 Jun 2022)");
  script_name("Adobe Media Encoder Multiple Arbitrary Code Execution Vulnerability (APSB21-70) - Windows");

  script_tag(name:"summary", value:"Adobe Media Encoder is prone to Arbitrary
  Code Execution vulnerabilities.");

  script_tag(name:"vuldetect", value:"The host is missing an important security
  update according to Adobe June update.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Access of Memory Location After End of Buffer.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to execute arbitrary code on an affected system.");

  script_tag(name:"affected", value:"Adobe Media Encoder 15.4 and earlier
  versions on Windows.");

  script_tag(name:"solution", value:"Update to Adobe Media Encoder 15.4.1 or
  later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/media-encoder/apsb21-70.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_media_encoder_detect_win.nasl");
  script_mandatory_keys("adobe/mediaencoder/win/detected");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less_equal(version:vers, test_version:"15.4")){
  report = report_fixed_ver(installed_version:vers, fixed_version:"15.4.1 or later", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);

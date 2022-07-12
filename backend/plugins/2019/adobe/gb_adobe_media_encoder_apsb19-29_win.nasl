# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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

CPE = "cpe:/a:adobe:media_encoder";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815081");
  script_version("2019-05-27T07:36:21+0000");
  script_cve_id("CVE-2019-7842", "CVE-2019-7844");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-27 07:36:21 +0000 (Mon, 27 May 2019)");
  script_tag(name:"creation_date", value:"2019-05-17 12:30:03 +0530 (Fri, 17 May 2019)");
  script_name("Adobe Media Encoder Security Updates(APSB19-29)-Windows");

  script_tag(name:"summary", value:"The host is installed with Adobe Media Encoder
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - An use-after-free error.

  - An out-of-bounds read error.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to conduct remote code execution and disclose sensitive information.");

  script_tag(name:"affected", value:"Adobe Media Encoder 13.0.2.");

  script_tag(name:"solution", value:"Upgrade to Adobe Media Encoder 13.1
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/media-encoder/apsb19-29.html");
  script_xref(name:"URL", value:"https://www.adobe.com/in/products/media-encoder.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_media_encoder_detect_win.nasl");
  script_mandatory_keys("adobe/mediaencoder/win/detected");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
ad_ver = infos['version'];
ad_path = infos['location'];

if(ad_ver == "13.0.2")
{
  report = report_fixed_ver(installed_version:ad_ver, fixed_version:"13.1", install_path:ad_path);
  security_message(data:report);
  exit(0);
}
exit(99);

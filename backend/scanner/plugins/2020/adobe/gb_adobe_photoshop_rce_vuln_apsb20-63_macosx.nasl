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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817601");
  script_version("2020-10-22T06:28:27+0000");
  script_cve_id("CVE-2020-24420");
  script_tag(name:"cvss_base", value:"9.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-10-22 10:10:52 +0000 (Thu, 22 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-10-21 11:26:46 +0530 (Wed, 21 Oct 2020)");
  script_name("Adobe Photoshop CC RCE Vulnerability-APSB20-63 (Mac OS X)");

  script_tag(name:"summary", value:"The host is installed with Adobe Photoshop
  CC and is prone to RCE vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"The flaw exists due to presence of an
  uncontrolled search path element.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code on affected system.");

  script_tag(name:"affected", value:"Adobe Photoshop CC 2019 20.0.10 and earlier
  and Adobe Photoshop 2020 21.2.2 and earlier versions on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Adobe Photoshop CC 2020 21.2.3
  or Photoshop CC 2021 22.0 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/photoshop/apsb20-63.html");

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_adobe_photoshop_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Photoshop/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

# nb: Photoshop 2020 gets registered as Photoshop
cpe_list = make_list("cpe:/a:adobe:photoshop_cc2019", "cpe:/a:adobe:photoshop");

if(!infos = get_app_version_and_location_from_list(cpe_list:cpe_list, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

# nb: 21.2.3 == 21.2.3.121?
if(vers =~ "^21\.") {
  if(version_is_less(version:vers, test_version:"21.2.3")) {
    fix = "21.2.3";
    installed_ver = "Adobe Photoshop CC 2020";
  }
}

else if(vers =~ "^20\.") {
  fix = "Adobe Photoshop CC 2020 or Adobe Photoshop 2021";
  installed_ver = "Adobe Photoshop CC 2019";
}

if(fix) {
  report = report_fixed_ver(installed_version:installed_ver + " " + vers, fixed_version:fix, install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);

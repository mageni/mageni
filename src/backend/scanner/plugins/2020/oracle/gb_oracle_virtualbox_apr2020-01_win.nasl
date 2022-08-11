# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from the referenced
# advisories, and are Copyright (C) by the respective right holder(s)
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

CPE = "cpe:/a:oracle:vm_virtualbox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.816846");
  script_version("2020-04-17T06:25:22+0000");
  script_cve_id("CVE-2020-2902", "CVE-2020-2959", "CVE-2020-2905", "CVE-2020-2908",
                "CVE-2020-2758", "CVE-2020-2894", "CVE-2020-2929", "CVE-2020-2911",
                "CVE-2020-2907", "CVE-2020-2958", "CVE-2020-2951", "CVE-2020-2741",
                "CVE-2020-2748", "CVE-2020-2909");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-04-17 09:53:31 +0000 (Fri, 17 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-04-15 08:39:55 +0530 (Wed, 15 Apr 2020)");
  script_name("Oracle VirtualBox Security Updates(apr2020) 01 - Windows");

  script_tag(name:"summary", value:"The host is installed with Oracle VM
  VirtualBox and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is
  present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to multiple errors
  in 'Core' component.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to
  have an impact on confidentiality, integrity and availability.");

  script_tag(name:"affected", value:"VirtualBox versions prior to 5.2.40, 6.1.x
  prior to 6.1.6 and 6.0.x prior to 6.0.20 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Oracle VirtualBox version 5.2.40
  or 6.0.20 or 6.1.6 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpuapr2020.html#AppendixOVIR");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_sun_virtualbox_detect_win.nasl");
  script_mandatory_keys("Oracle/VirtualBox/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);

virtualVer = infos['version'];
path = infos['location'];

if(virtualVer =~ "^6\.0\." && version_is_less(version:virtualVer, test_version:"6.0.20")){
  fix = "6.0.20";
}
else if(virtualVer =~ "^6\.1\." && version_is_less(version:virtualVer, test_version:"6.1.6")){
  fix = "6.1.6";
}
else if(version_is_less(version:virtualVer, test_version:"5.2.40")){
  fix = "5.2.40";
}

if(fix)
{
  report = report_fixed_ver( installed_version:virtualVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}
exit(0);

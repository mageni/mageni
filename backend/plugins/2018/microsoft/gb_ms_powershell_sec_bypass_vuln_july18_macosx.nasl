###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft PowerShell Core Security Feature Bypass Vulnerability July18 (Mac OS X)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:microsoft:powershell";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813699");
  script_version("2019-05-03T08:55:39+0000");
  script_cve_id("CVE-2018-8356");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2019-05-03 08:55:39 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2018-07-20 11:50:07 +0530 (Fri, 20 Jul 2018)");
  script_name("Microsoft PowerShell Core Security Feature Bypass Vulnerability July18 (Mac OS X)");

  script_tag(name:"summary", value:"This host is missing an important security
  update for PowerShell Core according to Microsoft security advisory
  CVE-2018-8356.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists when Microsoft .NET Framework
  components do not correctly validate certificates.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to present expired certificates when challenged.");

  script_tag(name:"affected", value:"PowerShell Core versions 6.x prior to 6.0.3
  and 6.1.x prior to 6.1.0-preview.4 on Mac OS X.");

  script_tag(name:"solution", value:"Update PowerShell Core to version 6.0.3 or
  6.1.0-preview.4 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://github.com/PowerShell/PowerShell");
  script_xref(name:"URL", value:"https://github.com/PowerShell/Announcements/issues/6");
  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-8356");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_powershell_core_detect_macosx.nasl");
  script_mandatory_keys("PowerShell/MacOSX/Version");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
psVer = infos['version'];
psPath = infos['location'];

if(version_in_range(version:psVer, test_version:"6.0", test_version2:"6.0.2")){
  fix = "6.0.3";
}
## 6.1.0-preview.4 = 6.1.0.4
else if(version_in_range(version:psVer, test_version:"6.1", test_version2:"6.1.0.3")){
  fix = "6.1.0-preview.4";
}

if(fix)
{
  report = report_fixed_ver(installed_version:psVer, fixed_version:fix, install_path:psPath);
  security_message(data:report);
  exit(0);
}
exit(0);

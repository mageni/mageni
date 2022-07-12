###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft PowerShell Core DoS And Security Feature Bypass Vulnerabilities (MacOSX)
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
  script_oid("1.3.6.1.4.1.25623.1.0.812745");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-0764", "CVE-2018-0786");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-01-30 15:21:20 +0530 (Tue, 30 Jan 2018)");
  script_name("Microsoft PowerShell Core DoS And Security Feature Bypass Vulnerabilities (MacOSX)");

  script_tag(name:"summary", value:"This host is missing an important security
  update for PowerShell Core according to Microsoft security update January 2018.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - An error in the open source versions of PowerShell Core when improper
    processing of XML documents by .NET Core occurs.

  - An error in the open source versions of PowerShell Core where an attacker
    could present a certificate that is marked invalid for a specific use,
    but a .NET Core component uses it for that purpose. This action disregards
    the Enhanced Key Usage tagging.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service to an application using PowerShell
  to process requests and also to bypass security.");

  script_tag(name:"affected", value:"PowerShell Core version 6.0.0 before 6.0.1");

  script_tag(name:"solution", value:"Update PowerShell Core to version 6.0.1 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://github.com/PowerShell/Announcements/issues/2");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gb_powershell_core_detect_macosx.nasl");
  script_mandatory_keys("PowerShell/MacOSX/Version");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

infos = "";
psPath = "";
psVer = "";

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
psVer = infos['version'];
psPath = infos['location'];

if(psVer =~ "^(6\.0)" && version_is_less(version:psVer, test_version:"6.0.1"))
{
  report = report_fixed_ver(installed_version:psVer, fixed_version:"6.0.1", install_path:psPath);
  security_message(data:report);
  exit(0);
}
exit(0);

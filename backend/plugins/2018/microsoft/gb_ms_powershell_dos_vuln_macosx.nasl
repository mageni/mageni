###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_powershell_dos_vuln_macosx.nasl 12120 2018-10-26 11:13:20Z mmartin $
#
# Microsoft PowerShell Core Denial of Service Vulnerability (MacOSX)
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
  script_oid("1.3.6.1.4.1.25623.1.0.813042");
  script_version("$Revision: 12120 $");
  script_cve_id("CVE-2018-0875");
  script_bugtraq_id(103225);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 13:13:20 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-03-16 11:09:04 +0530 (Fri, 16 Mar 2018)");
  script_name("Microsoft PowerShell Core Denial of Service Vulnerability (MacOSX)");

  script_tag(name:"summary", value:"This host is missing an important security
  update for PowerShell Core according to Microsoft security update March 2018.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists when .NET Core improperly
  handles specially crafted requests causing a hash collision.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to cause performance degrade resulting in a denial of service condition.");

  script_tag(name:"affected", value:"PowerShell Core version 6.0.0 before 6.0.2 on MacOSX");

  script_tag(name:"solution", value:"Update PowerShell Core to version 6.0.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://github.com/PowerShell/PowerShell/issues/6401");
  script_xref(name:"URL", value:"https://github.com/PowerShell/PowerShell/releases/tag/v6.0.2");
  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-0875");
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

if(psVer =~ "^(6\.0)" && version_is_less(version:psVer, test_version:"6.0.2"))
{
  report = report_fixed_ver(installed_version:psVer, fixed_version:"6.0.2", install_path:psPath);
  security_message(data:report);
  exit(0);
}
exit(0);

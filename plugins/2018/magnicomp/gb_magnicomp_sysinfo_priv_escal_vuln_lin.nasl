###############################################################################
# OpenVAS Vulnerability Test
#
# MagniComp SysInfo Privilege Escalation Vulnerability (Linux)
#
# Authors:
# Vidita V Koushik <vidita@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation;
# either version 2 of the License, or (at your option) any later version.
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

CPE = "cpe:/a:magnicomp:sysinfo";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814306");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2017-6516");
  script_bugtraq_id(96934);
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-10-03 12:54:15 +0530 (Wed, 03 Oct 2018)");
  script_name("MagniComp SysInfo Privilege Escalation Vulnerability (Linux)");

  script_tag(name:"summary", value:"This host is installed with MagniComp SysInfo
  and is prone to privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists because the application
  relies on information passed to it from the shell to see where it is installed
  and where to find the configuration file. Additionally, the application relies
  on arbitrary arguments to decide which applications to execute.");

  script_tag(name:"impact", value:"Successful exploitation allows local
  users to gain root privilege and hence full control over the affected system.");

  script_tag(name:"affected", value:"All versions of SysInfo prior to version
  10-H64");
  script_tag(name:"solution", value:"Update SysInfo to version 10-H64 or later. Please see the references for more information.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://labs.mwrinfosecurity.com/advisories/magnicomps-sysinfo-root-setuid-local-privilege-escalation-vulnerability");
  script_xref(name:"URL", value:"http://www.magnicomp.com/support/cve/CVE-2017-6516.shtml");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Privilege escalation");
  script_dependencies("gb_magnicomp_sysinfo_detect_lin.nasl");
  script_mandatory_keys("Sysinfo/Linux/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
mcsysVer = infos['version'];
mcsyspath = infos['location'];

if(version_is_less( version:mcsysVer, test_version:"10.0 H64"))
{
  report = report_fixed_ver(installed_version:mcsysVer, fixed_version:"10.0 H64");
  security_message(data:report);
  exit(0);
}

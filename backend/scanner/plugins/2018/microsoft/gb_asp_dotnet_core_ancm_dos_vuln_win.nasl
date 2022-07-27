###############################################################################
# OpenVAS Vulnerability Test
#
# ASP.NET Core ANCM Denial of Service Vulnerability (Windows)
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
##########################################################################

CPE = "cpe:/a:microsoft:asp.net_core";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813044");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-0808");
  script_bugtraq_id(103225);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-03-16 11:09:04 +0530 (Fri, 16 Mar 2018)");
  script_name("ASP.NET Core ANCM Denial of Service Vulnerability (Windows)");

  script_tag(name:"summary", value:"This host is installed with ASP.NET Core
  and is prone to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists when ASP.NET Core improperly
  handles web requests.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to cause a denial of service against an ASP.NET Core web application.");

  script_tag(name:"affected", value:"Microsoft ASP.NET Core 1.0, 1.1 and 2.0
  running AspNetCoreModule (ANCM) prior to 7.1.1990.0");

  script_tag(name:"solution", value:"Upgrade to AspNetCoreModule (ANCM) version
  7.1.1990.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://github.com/aspnet/Announcements/issues/294");
  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-0808");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("gb_asp_dotnet_core_detect_win.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("ASP.NET/Core/Ver");

  exit(0);
}

include("host_details.inc");
include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
coreVers = infos['version'];
path = infos['location'];

if(coreVers != "1.0" && coreVers != "1.1" && coreVers != "2.0"){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

acnmVer = fetch_file_version(sysPath:sysPath, file_name:"inetsrv\aspnetcore.dll");
if(!acnmVer){
  exit(0);
}

if(version_is_less(version:acnmVer, test_version:"7.1.1990.0"))
{
  report = report_fixed_ver(installed_version:"ASP .NET Core " + coreVers + " with ANCM " + acnmVer,
               fixed_version:"ASP .NET Core With ANCM 7.1.1990.0", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(0);

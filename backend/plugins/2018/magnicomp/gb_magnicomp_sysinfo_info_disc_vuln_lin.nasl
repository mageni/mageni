##############################################################################
# OpenVAS Vulnerability Test
#
# MagniComp SysInfo Information Disclosure Vulnerability (Linux)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.814060");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-7268");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-09-28 18:07:19 +0530 (Fri, 28 Sep 2018)");
  script_name("MagniComp SysInfo Information Disclosure Vulnerability (Linux)");

  script_tag(name:"summary", value:"This host is installed with MagniComp SysInfo
  and is prone to information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an access bypass error
  related to a combination of setuid binary and verbose debugging.");

  script_tag(name:"affected", value:"MagniComp SysInfo before version 10-H81.");

  script_tag(name:"solution", value:"Upgrade to MagniComp SysInfo 10-H81 or
  later. Please see the references for more information.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://dl.packetstormsecurity.net/1805-advisories/magnicomp-sysinfo-information-exposure.txt");
  script_xref(name:"URL", value:"https://www.magnicomp.com");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_magnicomp_sysinfo_detect_lin.nasl");
  script_mandatory_keys("Sysinfo/Linux/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
mgVer = infos['version'];
mgPath = infos['location'];

if(version_is_less(version:mgVer, test_version:"10.0 H81"))
{
  report = report_fixed_ver(installed_version:mgVer, fixed_version:"10-H81", install_path:mgPath);
  security_message(data:report);
  exit(0);
}
exit(99);

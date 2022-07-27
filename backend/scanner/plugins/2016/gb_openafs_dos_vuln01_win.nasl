###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openafs_dos_vuln01_win.nasl 12149 2018-10-29 10:48:30Z asteins $
#
# OpenAFS Denial of Service Vulnerability-01 (Windows)
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE= "cpe:/a:openafs:openafs";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808077");
  script_version("$Revision: 12149 $");
  script_cve_id("CVE-2015-3285");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-29 11:48:30 +0100 (Mon, 29 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-06-08 19:35:27 +0530 (Wed, 08 Jun 2016)");
  script_name("OpenAFS Denial of Service Vulnerability-01 (Windows)");

  script_tag(name:"summary", value:"This host is installed with OpenAFS and
  is prone to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to the kernel handling
  of the FS command for OSD uses a pointer to the wrong in-kernel memory
  when returning the result of the RPC.");

  script_tag(name:"impact", value:"Successful exploitation will allow local
  users to cause a denial of service (memory corruption and kernel panic) via
  a crafted OSD FS command.");

  script_tag(name:"affected", value:"OpenAFS version 1.0.3 through 1.6.12
  on Windows.");

  script_tag(name:"solution", value:"Update to OpenAFS version 1.6.13 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://www.openafs.org/pages/security/OPENAFS-SA-2015-004.txt");

  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_openafs_detect.nasl");
  script_mandatory_keys("OpenAFS/Win/Installed");
  script_xref(name:"URL", value:"https://www.openafs.org");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!afsVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_in_range(version:afsVer, test_version:"1.0.3", test_version2:"1.6.12"))
{
  report = report_fixed_ver(installed_version:afsVer, fixed_version: "1.6.13");
  security_message(data:report);
  exit(0);
}

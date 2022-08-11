###############################################################################
# OpenVAS Vulnerability Test
#
# VMware Tools Shared Folders Out-of-bounds read Vulnerability (Windows)
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

CPE = "cpe:/a:vmware:tools";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813700");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-6969");
  script_bugtraq_id(104737);
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-07-23 16:50:47 +0530 (Mon, 23 Jul 2018)");
  script_tag(name:"qod_type", value:"registry");
  script_name("VMware Tools Shared Folders Out-of-bounds read Vulnerability (Windows)");

  script_tag(name:"summary", value:"The host is installed with VMware Tools
  and is prone to an out of bounds read vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an out-of-bounds read
  vulnerability in the Shared Folders feature.");

  script_tag(name:"impact", value:"Successful exploitation will allow local
  attacker to obtain sensitive information that may aid in further attacks.");

  script_tag(name:"affected", value:"VMware Tools 10.x and prior on Windows.");

  script_tag(name:"solution", value:"Upgrade to VMware Tool version 10.3.0 or
  later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.vmware.com/security/advisories/VMSA-2018-0017.html");
  script_xref(name:"URL", value:"https://www.vmware.com");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_vmware_tools_detect_win.nasl");
  script_mandatory_keys("VMwareTools/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vmtoolVer = infos['version'];
vmPath = infos['location'];

if(version_is_less(version:vmtoolVer, test_version:"10.3.0"))
{
  report = report_fixed_ver(installed_version:vmtoolVer, fixed_version:"10.3.0", install_path:vmPath);
  security_message(data:report);
  exit(0);
}

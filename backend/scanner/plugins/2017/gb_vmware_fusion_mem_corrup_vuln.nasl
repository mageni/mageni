###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vmware_fusion_mem_corrup_vuln.nasl 11863 2018-10-12 09:42:02Z mmartin $
#
# VMware Fusion Memory Corruption Vulnerability-VMSA-2017-0005 (Mac OS X)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:vmware:fusion";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811266");
  script_version("$Revision: 11863 $");
  script_cve_id("CVE-2017-4901");
  script_bugtraq_id(96881);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 11:42:02 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-08-01 18:03:57 +0530 (Tue, 01 Aug 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("VMware Fusion Memory Corruption Vulnerability-VMSA-2017-0005 (Mac OS X)");

  script_tag(name:"summary", value:"The host is installed with VMware Fusion
  and is prone to memory corruption vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to error in the
  drag-and-drop (DnD) function in VMware Workstation which has an out-of-bounds
  memory access vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow a guest
  to execute code on the operating system that runs Fusion.");

  script_tag(name:"affected", value:"VMware Fusion 8.x before 8.5.5 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to VMware Fusion version 8.5.5
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.vmware.com/security/advisories/VMSA-2017-0005.html");

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_vmware_fusion_detect_macosx.nasl");
  script_mandatory_keys("VMware/Fusion/MacOSX/Version");
  script_xref(name:"URL", value:"http://www.vmware.com");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!vmwareVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(vmwareVer =~ "^8\.")
{
  if(version_is_less(version:vmwareVer, test_version:"8.5.5"))
  {
    report = report_fixed_ver(installed_version:vmwareVer, fixed_version:"8.5.5");
    security_message(data:report);
    exit(0);
  }
}

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vmware_fusion_rpc_dos_vuln_macosx.nasl 11874 2018-10-12 11:28:04Z mmartin $
#
# VMware Fusion 'RPC Command' Denial of Service Vulnerability (Mac OS X)
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
  script_oid("1.3.6.1.4.1.25623.1.0.810682");
  script_version("$Revision: 11874 $");
  script_cve_id("CVE-2015-2341");
  script_bugtraq_id(75094);
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:28:04 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-04-07 18:39:57 +0530 (Fri, 07 Apr 2017)");
  script_name("VMware Fusion 'RPC Command' Denial of Service Vulnerability (Mac OS X)");

  script_tag(name:"summary", value:"The host is installed with VMware Fusion
  and is prone to denial-of-service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an input validation
  issue on an RPC command.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct a denial of service condition.");

  script_tag(name:"affected", value:"VMware Fusion 6.x before 6.0.6 and 7.x
  before 7.0.1 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to VMware Fusion version 6.0.6
  or 7.0.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2015-0004.html");

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_vmware_fusion_detect_macosx.nasl");
  script_mandatory_keys("VMware/Fusion/MacOSX/Version");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!vmwareVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(vmwareVer =~ "^6\.")
{
  if(version_is_less(version:vmwareVer, test_version:"6.0.6"))
  {
    report = report_fixed_ver(installed_version:vmwareVer, fixed_version:"6.0.6");
    security_message(data:report);
    exit(0);
  }
}

else if(vmwareVer =~ "^7\.")
{
  if(version_is_less(version:vmwareVer, test_version:"7.0.1"))
  {
    report = report_fixed_ver(installed_version:vmwareVer, fixed_version:"7.0.1");
    security_message(data:report);
    exit(0);
  }
}
exit(0);

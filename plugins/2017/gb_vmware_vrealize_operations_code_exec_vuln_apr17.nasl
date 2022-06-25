##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vmware_vrealize_operations_code_exec_vuln_apr17.nasl 11874 2018-10-12 11:28:04Z mmartin $
#
# VMware vRealize Operations Remote Code Execution Vulnerability - Apr17
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

CPE = 'cpe:/a:vmware:vrealize_operations_manager';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811006");
  script_version("$Revision: 11874 $");
  script_cve_id("CVE-2015-6934");
  script_bugtraq_id(79648);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:28:04 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-04-21 10:42:44 +0530 (Fri, 21 Apr 2017)");
  script_name("VMware vRealize Operations Remote Code Execution Vulnerability - Apr17");

  script_tag(name:"summary", value:"This host is running VMware vRealize
  Operations and is prone to code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to a deserialization error
  involving Apache Commons-collections and a specially constructed chain of
  classes exists.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code in the context of current user.");

  script_tag(name:"affected", value:"VMware vRealize Operations 6.x before 6.2");

  script_tag(name:"solution", value:"Upgrade VMware vRealize Operations 6.2 or
  later.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2015-0009.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_vmware_vrealize_operations_manager_web_detect.nasl");
  script_mandatory_keys("vmware/vrealize/operations_manager/version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vmPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!vmVer = get_app_version(cpe:CPE, port:vmPort)){
  exit(0);
}

## vulnerable version 6.x before 6.2
if(vmVer =~ "^(6\.)")
{
  if(version_in_range(version:vmVer, test_version:"6.0", test_version2:"6.1"))
  {
    report = report_fixed_ver(installed_version:vmVer, fixed_version:"6.2");
    security_message(data:report, port:vmPort);
    exit(0);
  }
}

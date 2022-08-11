##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vmware_vrealize_orchestrator_code_exec_vuln_apr17.nasl 11863 2018-10-12 09:42:02Z mmartin $
#
# VMware vRealize Orchestrator Remote Code Execution Vulnerability - Apr17
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

CPE = 'cpe:/a:vmware:vrealize_orchestrator';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811005");
  script_version("$Revision: 11863 $");
  script_cve_id("CVE-2015-6934");
  script_bugtraq_id(79648);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 11:42:02 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-04-20 18:03:53 +0530 (Thu, 20 Apr 2017)");
  script_name("VMware vRealize Orchestrator Remote Code Execution Vulnerability - Apr17");

  script_tag(name:"summary", value:"This host is running VMware vRealize
  Orchestrator and is prone to code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to a deserialization error
  involving Apache Commons-collections and a specially constructed chain of
  classes exists.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code in the context of current user.");

  script_tag(name:"affected", value:"VMware vRealize Orchestrator 6.x before
  6.0.5, 4.2.x and 5.x");

  script_tag(name:"solution", value:"Upgrade VMware vRealize Orchestrator to
  version 6.0.5 or apply patch available from vendor.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable"); # unreliable as patch is also available
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2015-0009.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_vmware_vrealize_orchestrator_web_detect.nasl");
  script_mandatory_keys("vmware/vrealize/orchestrator/version");

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

##4.2.x, 5.x
if(vmVer =~ "^(4\.2\.)" || vmVer =~ "^(5\.)")
{
  VULN = TRUE;
  fix = "Apply Patch from Vendor";
}

## vulnerable version 6.x before 6.0.5
if(vmVer =~ "^(6\.)")
{
  if(version_in_range(version:vmVer, test_version:"6.0", test_version2:"6.0.4"))
  {
    VULN = TRUE;
    fix = "6.0.5 or Apply Patch from Vendor";
  }
}

if(VULN)
{
  report = report_fixed_ver(installed_version:vmVer, fixed_version:"6.0.5");
  security_message(data:report, port:vmPort);
  exit(0);
}

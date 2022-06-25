###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hpe_loadrunner_remote_code_exec_n_dos_vuln.nasl 11863 2018-10-12 09:42:02Z mmartin $
#
# HPE LoadRunner Multiple Remote Code Execution and Denial of Service Vulnerabilities
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/a:hp:loadrunner";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810935");
  script_version("$Revision: 11863 $");
  script_cve_id("CVE-2016-4359", "CVE-2016-4360", "CVE-2016-4361");
  script_bugtraq_id(90975);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 11:42:02 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-04-20 16:22:23 +0530 (Thu, 20 Apr 2017)");
  script_name("HPE LoadRunner Multiple Remote Code Execution and Denial of Service Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with HPE LoadRunner
  and is prone to multiple remote code execution and denial of service
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - An error within the import_csv functionality. The issue lies in the failure
    to restrict file paths sent to an unlink call which allows for the deletion
    of arbitrary files as SYSTEM.

  - An error within mchan.dll when constructing a shared memory file name.
    The issue lies in the failure to validate the size of a user-supplied string
    prior to copying it to a stack-based buffer.

  - A NULL pointer dereference error.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to cause a denial-of-service condition and execute arbitrary code
  on affected system.");

  script_tag(name:"affected", value:"HPE LoadRunner versions 11.52 through
  patch 3, 12.00 through patch 1, 12.01 through patch 3, 12.02 through
  patch 2, and 12.50 through patch 3.");

  script_tag(name:"solution", value:"Apply the mitigation actions provided
  in the link mentioned in the reference.");

  script_tag(name:"solution_type", value:"Mitigation");

  script_tag(name:"qod", value:"30");
  script_xref(name:"URL", value:"https://h20566.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c05157423");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1036006");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_hpe_loadrunner_detect.nasl");
  script_mandatory_keys("HPE/LoadRunner/Win/Ver");
  script_xref(name:"URL", value:"https://www.hpe.com");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!hpVer = get_app_version(cpe:CPE)){
  exit(0);
}

## Version is coming as 11.52.xx, 12.00.xx etc
## no version change after applying patch
## qod is reduced
if(hpVer =~ "^(11\.52)" ||
   hpVer =~ "^(12\.00)" ||
   hpVer =~ "^(12\.01)" ||
   hpVer =~ "^(12\.02)" ||
   hpVer =~ "^(12\.50)")
{
  report = report_fixed_ver(installed_version:hpVer, fixed_version:"Mitigation");
  security_message(data:report);
  exit(0);
}

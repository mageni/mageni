###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hpe_synergy_planning_tool_remote_code_exec_vuln.nasl 12338 2018-11-13 14:51:17Z asteins $
#
# HPE Synergy Planning Tool Remote Arbitrary Code Execution Vulnerability
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

CPE = "cpe:/a:hp:synergy_planning_tool";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809195");
  script_version("$Revision: 12338 $");
  script_cve_id("CVE-2016-4377");
  script_bugtraq_id(92479);
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-11-13 15:51:17 +0100 (Tue, 13 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-09-02 17:42:08 +0530 (Fri, 02 Sep 2016)");
  script_name("HPE Synergy Planning Tool Remote Arbitrary Code Execution Vulnerability");

  script_tag(name:"summary", value:"This host is installed with HPE Synergy
  Planning Tool and is prone to remote arbitrary code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an unspecified
  error.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  arbitrary code execution.");

  script_tag(name:"affected", value:"HPE Synergy Planning Tool prior
  to 3.3");

  script_tag(name:"solution", value:"Upgrade to HPE Synergy Planning Tool
  version 3.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c05237578");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_hpe_synergy_planning_tool_detect.nasl");
  script_mandatory_keys("HPE/Synergy/Planning/Tool/Win/Ver");

  script_xref(name:"URL", value:"https://www.hpe.com");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!hpVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:hpVer, test_version:"3.3"))
{
  report = report_fixed_ver(installed_version:hpVer, fixed_version:"3.3");
  security_message(data:report);
  exit(0);
}
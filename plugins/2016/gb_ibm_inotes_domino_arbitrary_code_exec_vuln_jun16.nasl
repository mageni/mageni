###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_inotes_domino_arbitrary_code_exec_vuln_jun16.nasl 12313 2018-11-12 08:53:51Z asteins $
#
# IBM INotes and Domino Arbitrary Code Execution Vulnerability - Jun16
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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

CPE = "cpe:/a:ibm:lotus_domino";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808112");
  script_version("$Revision: 12313 $");
  script_cve_id("CVE-2014-0892");
  script_bugtraq_id(67014);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-11-12 09:53:51 +0100 (Mon, 12 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-06-02 18:14:09 +0530 (Thu, 02 Jun 2016)");
  script_name("IBM INotes and Domino Arbitrary Code Execution Vulnerability - Jun16");

  script_tag(name:"summary", value:"This host is installed with IBM Domino and
  is prone to arbitrary code execution vulnerability");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an incorrect usage of
  gcc options.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to execute arbitrary code by leveraging the absence of the NX protection
  mechanism and placing crafted x86 code on the stack, aka SPR KLYH9GGS9W.");

  script_tag(name:"affected", value:"IBM iNotes and Domino 8.5.x before 8.5.3
  FP6 IF3 and 9.x before 9.0.1 FP1");

  script_tag(name:"solution", value:"Upgrade to IBM Domino 8.5.3 FP6 IF3,
  or 9.0.1 FP1, or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21670264");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_lotus_domino_detect.nasl");
  script_mandatory_keys("Domino/Installed");
  exit(0);
}

include("version_func.inc");
include("revisions-lib.inc"); # Used in get_highest_app_version
include("host_details.inc");

if(!domVer = get_highest_app_version(cpe:CPE)){
  exit(0);
}

domVer1 = ereg_replace(pattern:"FP", string:domVer, replace: ".");

if(version_in_range(version:domVer1, test_version:"8.5", test_version2:"8.5.3.6"))
{
  fix = "8.5.3 FP6 IF3";
  VULN = TRUE;
}

if(version_in_range(version:domVer1, test_version:"9.0.0", test_version2:"9.0.1"))
{
  fix = "9.0.1 FP1";
  VULN = TRUE;
}

if(VULN)
{
  report = report_fixed_ver(installed_version:domVer, fixed_version:fix);
  security_message(data:report, port:0);
  exit(0);
}

###############################################################################
# OpenVAS Vulnerability Test
# $Id: mageni_mcafee_agent_privsca_vuln.nasl 11816 2019-07-16 10:42:56Z yokaro $
#
# McAfee Agent (MA) Man-in-the-Middle Attack Vulnerability
#
# Authors:
# Yokaro <yokaro@mageni.net>
#
# Copyright:
# Copyright (C) 2022 Mageni Security, LLC
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

CPE = "cpe:/a:mcafee:mcafee_agent";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.315155");
  script_version("$Revision: 11816 $");
  script_cve_id("CVE-2022-0166","CVE-2021-31854");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2022-01-21 11:27:42 +0200 (Fri, 21 Jan 2022) $");
  script_tag(name:"creation_date", value:"2022-01-21 11:27:42 +0200 (Fri, 21 Jan 2022)");
  script_name("McAfee Agent (MA) Command Injection and Privilege Escalation Vulnerability Jan22");

  script_tag(name:"summary", value:"A command Injection Vulnerability in McAfee Agent (MA) for Windows prior to 5.7.5
  allows local users to inject arbitrary shell code into the file cleanup.exe. The malicious clean.exe file is placed
  into the relevant folder and executed by running the McAfee Agent deployment feature located in the System Tree.
  An attacker may exploit the vulnerability to obtain a reverse shell which can lead to privilege escalation to obtain root privileges.

  A privilege escalation vulnerability in the McAfee Agent prior to 5.7.5. McAfee Agent uses openssl.cnf during the build process to specify the
  OPENSSLDIR variable as a subdirectory within the installation directory. A low privilege user could have created subdirectories and executed
  arbitrary code with SYSTEM privileges by creating the appropriate pathway to the specifically created malicious openssl.cnf file.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to McAfee Agents weak directory permissions.");

  script_tag(name:"impact", value:"Privilege escalation and Command Injection");

  script_tag(name:"affected", value:"McAfee Agent version prior to 5.7.5");

  script_tag(name:"solution", value:"Upgrade to McAfee Agent 5.7.5.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10378");

  script_copyright("Copyright (C) 2022 Mageni Security LLC");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_mcafee_agent_detect.nasl");
  script_mandatory_keys("McAfee/Agent/Win/Ver");
  script_xref(name:"URL", value:"http://www.mcafee.com/us/");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!agentVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:agentVer, test_version:"5.7.5"))
{
  report = report_fixed_ver(installed_version:agentVer, fixed_version:"5.7.5");
  security_message(data:report);
  exit(0);
}

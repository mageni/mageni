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
# Copyright (C) 2019 Mageni Security, LLC
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

CPE = "cpe:/a:cylance:cylanceprotect:x64";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.315152");
  script_version("$Revision: 11816 $");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-08-26 12:42:56 +0200 (Mon, 26 Aug 2019) $");
  script_tag(name:"creation_date", value:"2019-08-26 16:26:54 +0530 (Mon, 26 Aug 2019)");
  script_name("Cylance Antivirus Susceptible to Concatenation Bypass");

  script_tag(name:"summary", value:"The Cylance AI-based antivirus product, prior to July 21, 2019, contains flaws that 
  allow an adversary to craft malicious files that the AV product will likely mistake for benign files.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Security researchers isolated properties of the machine learning algorithm allowing them 
  to change most known-malicious files in simple ways that cause the Cylance product to misclassify the file as benign. 
  Several common malware families, such as Dridex, Gh0stRAT, and Zeus, were reported as successfully modified to bypass the Cylance product in this way.");

  script_tag(name:"impact", value:"An attacker can easily and significantly improve their malware's defense evasion against 
  affected antivirus products. Unsophisticated attackers can leverage this flaw to change any executable to which they have access; 
  the defense evasion does not require rewriting the malware, just appending strings to it.");

  script_tag(name:"affected", value:"CylanceProtect less than and equal to 2.0.1533.2");

  script_tag(name:"solution", value:"Cylance has issued and automatically deployed a patch. Consider applying workarounds as well as the patch, as Cylance states in its response that 
  they had to remove features from the product and it is unclear whether or not this patch protects against all similar easy methods for forced misclassifications of malicious files.");

  script_tag(name:"solution_type", value:"Workaround");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://kb.cert.org/vuls/id/489481/");

  script_copyright("Copyright (C) 2019 Mageni Security LLC");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("mageni_cylance_detect_win.nasl");
  script_mandatory_keys("Cylance/Win/Ver");
  script_xref(name:"URL", value:"https://threatvector.cylance.com/en_us/home/resolution-for-blackberry-cylance-bypass.html");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!agentVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:agentVer, test_version:"2.0.1533.2"))
{
  report = report_fixed_ver(installed_version:agentVer, fixed_version:"2.0.1534.15");
  security_message(data:report);
  exit(0);
}

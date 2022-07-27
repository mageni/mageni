###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fortianalyzer_xss_vuln.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# FortiAnalyzer Reflected Cross Site Scripting Vulnerability - May 2015
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/h:fortinet:fortianalyzer";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805640");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2015-3620");
  script_bugtraq_id(74646);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-06-01 15:56:50 +0530 (Mon, 01 Jun 2015)");
  script_tag(name:"qod_type", value:"package");
  script_name("FortiAnalyzer Reflected Cross Site Scripting Vulnerability - May 2015");

  script_tag(name:"summary", value:"This host is installed with Fortinet
  Fortianalyzer and is prone to reflected cross-site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to the vulnerability in
  the advanced dataset reports page in Fortinet FortiAnalyzer.");

  script_tag(name:"impact", value:"Successful exploitation will allow a
  context-dependent attacker to create a specially crafted request that would
  execute arbitrary script code in a user's browser session within the trust
  relationship between their browser and the server.");

  script_tag(name:"affected", value:"Fortinet FortiAnalyzer versions 5.0.0
  through 5.0.10 and 5.2.0 through 5.2.1");

  script_tag(name:"solution", value:"Upgrade to Fortinet FortiAnalyzer 5.0.11 or
  5.2.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://fortiguard.com/psirt/FG-IR-15-005");

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("FortiOS Local Security Checks");
  script_dependencies("gb_fortianalyzer_version.nasl");
  script_mandatory_keys("fortianalyzer/version");
  script_xref(name:"URL", value:"http://www.fortinet.com");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!fazVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_in_range(version:fazVer, test_version:"5.0.0", test_version2:"5.0.10"))
{
  VULN = TRUE;
  fix = "5.0.11";
}
if(version_in_range(version:fazVer, test_version:"5.2.0", test_version2:"5.2.1"))
{
  VULN = TRUE;
  fix = "5.2.2";
}
if(VULN)
{
  report = 'Installed version: ' + fazVer + '\n' +
           'Fixed version:     ' + fix + '\n';
  security_message(data:report);
  exit(0);
}

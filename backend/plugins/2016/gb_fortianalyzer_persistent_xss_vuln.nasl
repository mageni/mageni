###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fortianalyzer_persistent_xss_vuln.nasl 12455 2018-11-21 09:17:27Z cfischer $
#
# FortiAnalyzer Persistent Cross Site Scripting Vulnerability
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

CPE = "cpe:/h:fortinet:fortianalyzer";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809262");
  script_version("$Revision: 12455 $");
  script_cve_id("CVE-2016-3196");
  script_bugtraq_id(92265);
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-11-21 10:17:27 +0100 (Wed, 21 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-09-21 10:02:40 +0530 (Wed, 21 Sep 2016)");
  script_tag(name:"qod_type", value:"package");
  script_name("FortiAnalyzer Persistent Cross Site Scripting Vulnerability");

  script_tag(name:"summary", value:"This host is installed with Fortinet
  Fortianalyzer and is prone to persistent cross-site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists When a low privileged user
  uploads images in the report section, the filenames are not properly sanitized.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  authenticated users to inject arbitrary web script.");

  script_tag(name:"affected", value:"Fortinet FortiAnalyzer versions 5.0.0
  through 5.0.11 and 5.2.0 through 5.2.5");

  script_tag(name:"solution", value:"Upgrade to Fortinet FortiAnalyzer 5.0.12 or
  5.2.6 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://fortiguard.com/advisory/fortimanager-and-fortianalyzer-persistent-xss-vulnerability");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("FortiOS Local Security Checks");
  script_dependencies("gb_fortianalyzer_version.nasl");
  script_mandatory_keys("fortianalyzer/version");
  script_xref(name:"URL", value:"http://www.fortinet.com");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!fortianalyzerVer = get_app_version(cpe:CPE)){
exit(0);
}

if(version_in_range(version:fortianalyzerVer, test_version:"5.0.0", test_version2:"5.0.11"))
{
  VULN = TRUE;
  fix = "5.0.12";
}

else if(version_in_range(version:fortianalyzerVer, test_version:"5.2.0", test_version2:"5.2.5"))
{
  VULN = TRUE;
  fix = "5.2.6";
}

if(VULN)
{
  report = report_fixed_ver(installed_version:fortianalyzerVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}

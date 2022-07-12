###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_typo3_mult_xss_vuln_jan16.nasl 12455 2018-11-21 09:17:27Z cfischer $
#
# TYPO3 Multiple Cross-Site Scripting Vulnerabilities - Jan16
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

CPE = "cpe:/a:typo3:typo3";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806665");
  script_version("$Revision: 12455 $");
  script_cve_id("CVE-2015-8759", "CVE-2015-8758", "CVE-2015-8757", "CVE-2015-8755");
  script_bugtraq_id(79250, 79240, 79254, 79236);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-11-21 10:17:27 +0100 (Wed, 21 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-01-19 12:41:21 +0530 (Tue, 19 Jan 2016)");
  script_name("TYPO3 Multiple Cross-Site Scripting Vulnerabilities - Jan16");

  script_tag(name:"summary", value:"This host is installed with TYPO3 and
  is prone to multiple cross-site scripting vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - An error in authorized editors which can insert javascript commands by using
  the url scheme 'javascript:'.

  - An error in editor where input passed to editor is not properly encoded.

  - An error while HTML encode extension data during an extension installation.

  - An error while encoding user input.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attackers to execute arbitrary script code in a user's browser session
  within the trust relationship between their browser and the server.");

  script_tag(name:"affected", value:"TYPO3 versions 6.2.x before 6.2.16 and 7.x
  before 7.6.1");

  script_tag(name:"solution", value:"Upgrade to TYPO3 version 6.2.16 or 7.6.1
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://typo3.org/teams/security/security-bulletins/typo3-core/typo3-core-sa-2015-011");
  script_xref(name:"URL", value:"http://typo3.org/teams/security/security-bulletins/typo3-core/typo3-core-sa-2015-010");
  script_xref(name:"URL", value:"http://typo3.org/teams/security/security-bulletins/typo3-core/typo3-core-sa-2015-013");
  script_xref(name:"URL", value:"http://typo3.org/teams/security/security-bulletins/typo3-core/typo3-core-sa-2015-012");

  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_typo3_detect.nasl");
  script_mandatory_keys("TYPO3/installed");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"https://typo3.org/typo3-cms");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!typoPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!typoVer = get_app_version(cpe:CPE, port:typoPort)){
  exit(0);
}

if(typoVer !~ "[0-9]+\.[0-9]+\.[0-9]+") exit(0); # Version is not exact enough

if(typoVer =~ "6\.2")
{
  if(version_in_range(version:typoVer, test_version:"6.2.0", test_version2:"6.2.15"))
  {
    fix = "6.2.16";
    VULN = TRUE;
  }
}

if(typoVer =~ "7\.")
{
  if(version_in_range(version:typoVer, test_version:"7.0", test_version2:"7.6.0"))
  {
    fix = "7.6.1";
    VULN = TRUE;
  }
}

if(VULN)
{
  report = report_fixed_ver(installed_version:typoVer, fixed_version:fix);
  security_message(port:typoPort, data:report);
  exit(0);
}

exit(99);

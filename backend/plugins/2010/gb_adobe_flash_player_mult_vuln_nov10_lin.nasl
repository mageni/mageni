###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_flash_player_mult_vuln_nov10_lin.nasl 12653 2018-12-04 15:31:25Z cfischer $
#
# Adobe Flash Player Multiple Vulnerabilities (Linux)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801630");
  script_version("$Revision: 12653 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-04 16:31:25 +0100 (Tue, 04 Dec 2018) $");
  script_tag(name:"creation_date", value:"2010-11-12 15:34:28 +0100 (Fri, 12 Nov 2010)");
  script_cve_id("CVE-2010-3636", "CVE-2010-3637", "CVE-2010-3638", "CVE-2010-3639",
                "CVE-2010-3640", "CVE-2010-3641", "CVE-2010-3642", "CVE-2010-3643",
                "CVE-2010-3644", "CVE-2010-3645", "CVE-2010-3646", "CVE-2010-3647",
                "CVE-2010-3648", "CVE-2010-3649", "CVE-2010-3650", "CVE-2010-3652");
  script_bugtraq_id(44669);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Adobe Flash Player Multiple Vulnerabilities (Linux)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/41917");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb10-26.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_lin.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Linux/Ver");
  script_tag(name:"impact", value:"Successful exploitation will let attackers to execute arbitrary code or cause
  a denial of service via unknown vectors.");
  script_tag(name:"affected", value:"Adobe Flash Player version 10.1.85.3 and prior on Linux");
  script_tag(name:"insight", value:"The flaws are caused by unspecified errors, that can be exploited to execute
  arbitrary code or cause a denial of service.");
  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player version 10.1.102.64 or later");
  script_tag(name:"summary", value:"This host is installed with Adobe Flash Player and is prone to
  multiple unspecified vulnerabilities.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.adobe.com/downloads/");
  exit(0);
}


include("version_func.inc");

flashVer = get_kb_item("AdobeFlashPlayer/Linux/Ver");
flashVer = ereg_replace(pattern:",", string:flashVer, replace: ".");

if(flashVer)
{
  if(version_in_range(version:flashVer, test_version:"10", test_version2:"10.1.85.3")||
     version_is_less(version:flashVer, test_version:"9.0.289.0")) {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}

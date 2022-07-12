###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_flash_player_mult_vuln_jun12_lin.nasl 14117 2019-03-12 14:02:42Z cfischer $
#
# Adobe Flash Player Multiple Vulnerabilities June-2012 (Linux)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802873");
  script_version("$Revision: 14117 $");
  script_cve_id("CVE-2012-2034", "CVE-2012-2035", "CVE-2012-2036", "CVE-2012-2037",
                "CVE-2012-2039", "CVE-2012-2038", "CVE-2012-2040");
  script_bugtraq_id(53887);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 15:02:42 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-06-20 10:16:16 +0530 (Wed, 20 Jun 2012)");
  script_name("Adobe Flash Player Multiple Vulnerabilities June-2012 (Linux)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/49388");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1027139");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb12-14.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_lin.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Linux/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to bypass certain security
  restrictions, execute arbitrary code in the context of the browser or cause
  a denial of service (memory corruption) via unspecified vectors.");
  script_tag(name:"affected", value:"Adobe Flash Player version before 10.3.183.20,
  Adobe Flash Player version 11.x through 11.2.202.235 on Linux.");
  script_tag(name:"insight", value:"Multiple errors are caused,

  - When parsing ActionScript.

  - Within NPSWF32.dll when parsing certain tags.

  - In the 'SoundMixer.computeSpectrum()' method, which can be exploited to
    bypass the same-origin policy.

  - In the installer allows planting a binary file.");
  script_tag(name:"solution", value:"Update to Adobe Flash Player version 10.3.183.20 or 11.2.202.236 or later.");

  script_tag(name:"summary", value:"This host is installed with Adobe Flash Player and is prone to
  multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

flashVer = get_kb_item("AdobeFlashPlayer/Linux/Ver");

if(flashVer && flashVer =~ ",")
{
  flashVer = ereg_replace(pattern:",", string:flashVer, replace: ".");
}

if(flashVer)
{
  if(version_is_less(version: flashVer, test_version:"10.3.183.20")||
     version_in_range(version: flashVer, test_version:"11.0", test_version2:"11.2.202.235")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}

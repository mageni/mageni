###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_air_mult_vuln_jun12_macosx.nasl 11883 2018-10-12 13:31:09Z cfischer $
#
# Adobe Air Multiple Vulnerabilities June-2012 (Mac OS X)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803812");
  script_version("$Revision: 11883 $");
  script_cve_id("CVE-2012-2034", "CVE-2012-2035", "CVE-2012-2036", "CVE-2012-2037",
                "CVE-2012-2039", "CVE-2012-2038", "CVE-2012-2040");
  script_bugtraq_id(53887);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:31:09 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-07-11 15:01:50 +0530 (Thu, 11 Jul 2013)");
  script_name("Adobe Air Multiple Vulnerabilities June-2012 (Mac OS X)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/49388");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1027139");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb12-14.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Air/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to bypass certain security
  restrictions, execute arbitrary code in the context of the browser or cause
  a denial of service (memory corruption) via unspecified vectors.");
  script_tag(name:"affected", value:"Adobe AIR version 3.2.0.2070 and prior on Mac OS X");
  script_tag(name:"insight", value:"Multiple errors are caused,

  - When parsing ActionScript.

  - Within NPSWF32.dll when parsing certain tags.

  - In the 'SoundMixer.computeSpectrum()' method, which can be exploited to
    bypass the same-origin policy.

  - In the installer allows planting a binary file.");
  script_tag(name:"solution", value:"Update to Adobe Air version 3.3.0.3610 or later.");
  script_xref(name:"URL", value:"http://get.adobe.com/air");
  script_tag(name:"summary", value:"This host is installed with Adobe Air and is prone to multiple
  vulnerabilities.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

airVer = get_kb_item("Adobe/Air/MacOSX/Version");
if(airVer)
{
  if(version_is_less_equal(version: airVer, test_version:"3.2.0.2070"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

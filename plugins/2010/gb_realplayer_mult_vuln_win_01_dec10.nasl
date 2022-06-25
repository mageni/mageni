###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_realplayer_mult_vuln_win_01_dec10.nasl 12653 2018-12-04 15:31:25Z cfischer $
#
# RealNetworks RealPlayer Multiple Vulnerabilities (Windows) - Dec 10
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Updated By: Sooraj KS <kssooraj@secpod.com> on 2011-01-03
#   Added the related CVEs and description.
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
  script_oid("1.3.6.1.4.1.25623.1.0.801672");
  script_version("$Revision: 12653 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-04 16:31:25 +0100 (Tue, 04 Dec 2018) $");
  script_tag(name:"creation_date", value:"2010-12-29 07:31:27 +0100 (Wed, 29 Dec 2010)");
  script_bugtraq_id(44144);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-2579", "CVE-2010-0125", "CVE-2010-4379",
                "CVE-2010-4380", "CVE-2010-4381", "CVE-2010-4382",
                "CVE-2010-4383", "CVE-2010-4385", "CVE-2010-4386",
                "CVE-2010-4387", "CVE-2010-3747", "CVE-2010-3748",
                "CVE-2010-3749", "CVE-2010-3750", "CVE-2010-3751",
                "CVE-2010-2578");
  script_name("RealNetworks RealPlayer Multiple Vulnerabilities (Windows) - Dec10");
  script_xref(name:"URL", value:"http://secunia.com/advisories/38550/");
  script_xref(name:"URL", value:"http://service.real.com/realplayer/security/12102010_player/en/");
  script_xref(name:"URL", value:"http://service.real.com/realplayer/security/10152010_player/en/");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_realplayer_detect_win.nasl");
  script_mandatory_keys("RealPlayer/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to execute arbitrary
  code or cause a denial of service.");
  script_tag(name:"affected", value:"RealPlayer SP 1.0 to 1.1.4 (12.x)
  RealNetworks RealPlayer SP 11.0 to 11.1 on Windows platform.");
  script_tag(name:"insight", value:"The multiple flaws are due to,

  - An error in the 'Cook' codec initialization function

  - Heap-based buffer overflow errors when parsing 'SIPR', 'AAC', 'RealMedia',
    'RA5' and 'SOUND' files

  - Integer overflow in the handling of frame dimensions in a 'SIPR' stream

  - An uninitialized pointer vulnerability exists in the CDDA URI ActiveX
    Control.

  - A stack-based buffer overflow in the RichFX component.

  - Heap-based buffer overflow error via a crafted 'QCP' file.

  - A parameter injection vulnerability in the RecordClip browser extension.

  - rjrmrpln.dll does not properly validate file contents that are used during
    interaction with a heap buffer.

  - Multiple heap-based buffer overflows in an ActiveX control allow remote
    attackers to execute arbitrary code via a long .smil argument to the tfile,
    pnmm, cdda protocol handler.");
  script_tag(name:"solution", value:"Upgrade to RealPlayer 14.0.1.609 (Build 12.0.1.609) or later.");
  script_tag(name:"summary", value:"This host is installed with RealPlayer which is prone to multiple
  vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.real.com/player");
  exit(0);
}


include("version_func.inc");

rpVer = get_kb_item("RealPlayer/Win/Ver");
if(isnull(rpVer)){
  exit(0);
}

## Realplayer version 11.x, 1.x(12.x)
if(version_in_range(version:rpVer, test_version:"11.0.0", test_version2:"11.0.0.674") ||
   version_in_range(version:rpVer, test_version:"12.0.0", test_version2:"12.0.0.873")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

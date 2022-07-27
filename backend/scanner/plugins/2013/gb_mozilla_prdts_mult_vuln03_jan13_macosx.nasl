###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_prdts_mult_vuln03_jan13_macosx.nasl 11866 2018-10-12 10:12:29Z cfischer $
#
# Mozilla Products Multiple Vulnerabilities-03 January13 (Mac OS X)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.803203");
  script_version("$Revision: 11866 $");
  script_cve_id("CVE-2013-0761", "CVE-2013-0763", "CVE-2013-0771", "CVE-2013-0749");
  script_bugtraq_id(57196, 57197, 57198, 57205);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:12:29 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-01-16 16:30:40 +0530 (Wed, 16 Jan 2013)");
  script_name("Mozilla Products Multiple Vulnerabilities-03 January13 (Mac OS X)");

  script_xref(name:"URL", value:"http://secunia.com/advisories/51752/");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1027955");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1027957");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1027958");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-01.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-02.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Mac/Installed");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to cause a denial of service
  or execute arbitrary code in the context of the browser.");

  script_tag(name:"affected", value:"SeaMonkey version before 2.15 on Mac OS X

  Thunderbird version before 17.0.2 on Mac OS X

  Mozilla Firefox version before 18.0 on Mac OS X

  Thunderbird ESR version 17.x before 17.0.1 on Mac OS X

  Mozilla Firefox ESR version 17.x before 17.0.1 on Mac OS X");

  script_tag(name:"insight", value:"- Use-after-free errors exists within the
    'mozilla::TrackUnionStream::EndTrack' implementation and Mesa when resizing
    a WebGL canvas.

  - Unspecified error in the browser engine can be exploited to corrupt memory.

  - An error within the 'gfxTextRun::ShrinkToLigatureBoundaries()' function.");

  script_tag(name:"summary", value:"This host is installed with Mozilla Firefox/Thunderbird/Seamonkey and is
  prone to multiple vulnerabilities.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 18.0 or ESR version 17.0.1 or later, upgrade to SeaMonkey version to 2.15 or later,
  upgrade to Thunderbird version to 17.0.2 or ESR version 17.0.1 or later.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.mozilla.com/en-US/firefox/all.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/projects/seamonkey/");
  script_xref(name:"URL", value:"http://www.mozilla.org/en-US/thunderbird/");
  exit(0);
}

include("version_func.inc");

ffVer = get_kb_item("Mozilla/Firefox/MacOSX/Version");
fesrVer = get_kb_item("Mozilla/Firefox-ESR/MacOSX/Version");

if(ffVer || fesrVer)
{
  if(version_is_less(version:ffVer, test_version:"18.0")||
     version_is_equal(version:fesrVer, test_version:"17.0.0"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

seaVer = get_kb_item("SeaMonkey/MacOSX/Version");

if(seaVer)
{
  if(version_is_less(version:seaVer, test_version:"2.15"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

tbVer = get_kb_item("ThunderBird/MacOSX/Version");
tbesrVer = get_kb_item("ThunderBird-ESR/MacOSX/Version");

if(tbVer || tbesrVer)
{
  if(version_is_less(version:tbVer, test_version:"17.0.2")||
     version_is_equal(version:tbesrVer, test_version:"17.0.0"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

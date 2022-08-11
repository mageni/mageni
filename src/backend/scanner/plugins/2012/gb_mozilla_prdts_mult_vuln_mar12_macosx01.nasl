###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_prdts_mult_vuln_mar12_macosx01.nasl 11861 2018-10-12 09:29:59Z cfischer $
#
# Mozilla Products Multiple Vulnerabilities - Mar12 (Mac OS X 01)
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
  script_oid("1.3.6.1.4.1.25623.1.0.802823");
  script_version("$Revision: 11861 $");
  script_cve_id("CVE-2012-0451", "CVE-2012-0454", "CVE-2012-0459", "CVE-2012-0460",
                 "CVE-2012-0462");
  script_bugtraq_id(52463, 52455, 52457, 52456, 52467);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 11:29:59 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-03-20 13:52:53 +0530 (Tue, 20 Mar 2012)");
  script_name("Mozilla Products Multiple Vulnerabilities - Mar12 (Mac OS X 01)");

  script_xref(name:"URL", value:"http://secunia.com/advisories/48402");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-12.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-15.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-17.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-18.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-19.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Mac/Installed");
  script_tag(name:"impact", value:"Successful exploitation will let attackers to cause a denial of service or
  possibly execute arbitrary code or inject html code via unknown vectors.");
  script_tag(name:"affected", value:"SeaMonkey version before 2.8,
  Thunderbird version 5.0 through 10.0,
  Mozilla Firefox version 4.x through 10.0,
  Thunderbird ESR version 10.x before 10.0.3,
  Mozilla Firefox ESR version 10.x before 10.0.3.");
  script_tag(name:"insight", value:"The flaws are due to

  - An improper write access restriction to the window.fullScreen object.

  - Multiple unspecified vulnerabilities in the browser engine.

  - An improper implementation of the Cascading Style Sheets (CSS) allowing to
    crash the service when accessing keyframe cssText after dynamic
    modification.

  - A use-after-free error within the shlwapi.dll when closing a child window
    that uses the file open dialog.

  - An error when handling Content Security Policy headers.");
  script_tag(name:"summary", value:"The host is installed with Mozilla firefox/thunderbird/seamonkey and is prone
  to multiple vulnerabilities.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 11.0 or ESR version 10.0.3 later, Upgrade to SeaMonkey version to 2.8 or later
  upgrade to Thunderbird version to 11 or ESR version 10.0.3 later.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.mozilla.com/en-US/firefox/all.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/projects/seamonkey/");
  script_xref(name:"URL", value:"http://www.mozilla.org/en-US/thunderbird/");
  exit(0);
}


include("version_func.inc");

ffVer = get_kb_item("Mozilla/Firefox/MacOSX/Version");

if(!isnull(ffVer))
{
  if(version_in_range(version:ffVer, test_version:"4.0", test_version2:"10.0.2"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}

seaVer = get_kb_item("SeaMonkey/MacOSX/Version");

if(!isnull(seaVer))
{
  if(version_is_less(version:seaVer, test_version:"2.8"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}

tbVer = get_kb_item("ThunderBird/MacOSX/Version");

if(!isnull(tbVer))
{
  if(version_in_range(version:tbVer, test_version:"5.0", test_version2:"10.0.2")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}

exit(0);

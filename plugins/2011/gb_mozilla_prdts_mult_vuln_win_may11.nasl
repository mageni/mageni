###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_prdts_mult_vuln_win_may11.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Mozilla Products Multiple Vulnerabilities May-11 (Windows)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801883");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-05-18 15:37:30 +0200 (Wed, 18 May 2011)");
  script_cve_id("CVE-2011-0065", "CVE-2011-0066", "CVE-2011-0067", "CVE-2011-0073");
  script_bugtraq_id(47659, 47662, 47667, 47663);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Mozilla Products Multiple Vulnerabilities May-11 (Windows)");

  script_xref(name:"URL", value:"http://secunia.com/advisories/44357/");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/1127");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-12.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl", "gb_seamonkey_detect_win.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed");
  script_tag(name:"impact", value:"Successful exploitation will let remote attackers to execute arbitrary code.");
  script_tag(name:"affected", value:"SeaMonkey versions before 2.0.14.
  Mozilla Firefox versions before 3.5.19 and 3.6.x before 3.6.17.");
  script_tag(name:"insight", value:"- Multiple use-after-free errors within the handling of the 'mChannel',
    'mObserverList', and 'nsTreeRange' object attributes can be exploited
    to execute arbitrary code.

  - An error when handling Java applets can be exploited to steal entries
    from the form history via the autocomplete controls.");
  script_tag(name:"summary", value:"The host is installed with Mozilla Firefox or Seamonkey and is prone to
  multiple vulnerabilities.");
  script_tag(name:"solution", value:"Upgrade to Firefox version 3.5.19 or 3.6.17 or later,
  Upgrade to Seamonkey version 2.0.14 or later.");
  script_xref(name:"URL", value:"http://www.mozilla.com/en-US/firefox/all.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/projects/seamonkey/");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("version_func.inc");


ffVer = get_kb_item("Firefox/Win/Ver");
if(ffVer)
{
  if(version_is_less(version:ffVer, test_version:"3.5.19") ||
     version_in_range(version:ffVer, test_version:"3.6.0", test_version2:"3.6.16"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

smVer = get_kb_item("Seamonkey/Win/Ver");
if(smVer != NULL)
{
  if(version_is_less(version:smVer, test_version:"2.0.14")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}

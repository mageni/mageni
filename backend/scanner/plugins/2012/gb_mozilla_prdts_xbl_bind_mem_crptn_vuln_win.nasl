###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_prdts_xbl_bind_mem_crptn_vuln_win.nasl 11861 2018-10-12 09:29:59Z cfischer $
#
# Mozilla Products XBL Binding Memory Corruption Vulnerability - (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802592");
  script_version("$Revision: 11861 $");
  script_cve_id("CVE-2012-0452");
  script_bugtraq_id(51975);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 11:29:59 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-02-14 15:40:12 +0530 (Tue, 14 Feb 2012)");
  script_name("Mozilla Products XBL Binding Memory Corruption Vulnerability - (Windows)");

  script_xref(name:"URL", value:"http://secunia.com/advisories/48008/");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1026665");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-10.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl", "gb_seamonkey_detect_win.nasl",
                      "gb_thunderbird_detect_portable_win.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed");
  script_tag(name:"impact", value:"Successful exploitation will let attackers to execute arbitrary code in the
  context of the user running the affected application. Failed exploit attempts
  will likely result in denial-of-service conditions.");
  script_tag(name:"affected", value:"SeaMonkey version prior to 2.7.1,
  Thunderbird version 10.x prior to 10.0.1 and
  Mozilla Firefox version 10.x prior to 10.0.1 on Windows");
  script_tag(name:"insight", value:"The flaw is due to an error in the 'ReadPrototypeBindings()' method
  when handling XBL bindings in a hash table and can be exploited to cause a
  cycle collector to call an invalid virtual function.");
  script_tag(name:"summary", value:"The host is installed with Mozilla firefox/seamonkey/thunderbird
  and is prone to memory corruption vulnerability.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 10.0.1 or later, upgrade to SeaMonkey version to 2.7.1 or later,
  upgrade to Thunderbird version 10.0.1 or later.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.mozilla.com/en-US/firefox/all.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/projects/seamonkey/");
  script_xref(name:"URL", value:"http://www.mozilla.org/en-US/thunderbird/");
  exit(0);
}

include("version_func.inc");

ffVer = get_kb_item("Firefox/Win/Ver");
if(!isnull(ffVer))
{
  if(version_is_equal(version:ffVer, test_version:"10.0"))
  {
     security_message( port: 0, data: "The target host was found to be vulnerable" );
     exit(0);
  }
}

seaVer = get_kb_item("Seamonkey/Win/Ver");
if(!isnull(seaVer))
{
  if(version_is_equal(version:seaVer, test_version:"2.7"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

tbVer = get_kb_item("Thunderbird/Win/Ver");
if(!isnull(tbVer))
{
  if(version_is_equal(version:tbVer, test_version:"10.0")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}

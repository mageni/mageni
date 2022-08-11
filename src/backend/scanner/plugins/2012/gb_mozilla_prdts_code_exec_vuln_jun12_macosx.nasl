###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_prdts_code_exec_vuln_jun12_macosx.nasl 11861 2018-10-12 09:29:59Z cfischer $
#
# Mozilla Products 'nsHTMLSelectElement' Remote Code Execution Vulnerability (Mac)
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
  script_oid("1.3.6.1.4.1.25623.1.0.802875");
  script_version("$Revision: 11861 $");
  script_cve_id("CVE-2011-3671");
  script_bugtraq_id(54080);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 11:29:59 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-06-20 13:43:30 +0530 (Wed, 20 Jun 2012)");
  script_name("Mozilla Products 'nsHTMLSelectElement' Remote Code Execution Vulnerability (Mac)");

  script_xref(name:"URL", value:"http://secunia.com/advisories/47302");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1027183");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-41.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Mac/Installed");
  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute arbitrary
  code in the context of the browser.");
  script_tag(name:"affected", value:"SeaMonkey version before 2.6,
  Thunderbird version 5.0 through 8.0,
  Mozilla Firefox version 4.x through 8.0 on Mac OS X.");
  script_tag(name:"insight", value:"A use-after-free error exists in 'nsHTMLSelectElement' when the parent node
  of the element is no longer active.");
  script_tag(name:"summary", value:"This host is installed with Mozilla firefox/thunderbird/seamonkey and is prone
  to remote code execution vulnerability.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 9.0 or later, upgrade to SeaMonkey version to 2.6 or later,
  upgrade to Thunderbird version to 9.0 or later.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.mozilla.com/en-US/firefox/all.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/projects/seamonkey/");
  script_xref(name:"URL", value:"http://www.mozilla.org/en-US/thunderbird/");

  exit(0);
}


include("version_func.inc");

ffVer = get_kb_item("Mozilla/Firefox/MacOSX/Version");

if(ffVer)
{
  if(version_in_range(version:ffVer, test_version:"4.0", test_version2:"8.0"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

seaVer = get_kb_item("SeaMonkey/MacOSX/Version");

if(seaVer)
{
  if(version_is_less(version:seaVer, test_version:"2.6"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

tbVer = get_kb_item("ThunderBird/MacOSX/Version");

if(tbVer)
{
  if(version_in_range(version:tbVer, test_version:"5.0", test_version2:"8.0"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

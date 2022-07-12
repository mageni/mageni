###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_opera_mult_vuln_dec08_win.nasl 12623 2018-12-03 13:11:38Z cfischer $
#
# Opera Web Browser Multiple Vulnerabilities - Dec08 (Windows)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (c) 2008 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900081");
  script_version("$Revision: 12623 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-03 14:11:38 +0100 (Mon, 03 Dec 2018) $");
  script_tag(name:"creation_date", value:"2008-12-26 14:23:17 +0100 (Fri, 26 Dec 2008)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-5679", "CVE-2008-5680", "CVE-2008-5681",
                "CVE-2008-5682", "CVE-2008-5683");
  script_bugtraq_id(32864);
  script_name("Opera Web Browser Multiple Vulnerabilities - Dec08 (Windows)");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/920/");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/921/");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/923/");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/924/");
  script_xref(name:"URL", value:"http://www.opera.com/docs/changelogs/windows/963/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 SecPod");
  script_family("Buffer overflow");
  script_dependencies("gb_opera_detect_portable_win.nasl");
  script_mandatory_keys("Opera/Win/Version");

  script_tag(name:"impact", value:"Successful remote attack could inject arbitrary code, information disclosure,
  execute java or plugin content and can even crash the application.");

  script_tag(name:"affected", value:"Opera version prior to 9.63 on Windows.");

  script_tag(name:"insight", value:"The flaws are due to

  - a buffer overflow error when handling certain text-area contents.

  - a memory corruption error when processing certain HTML constructs.

  - an input validation error in the feed preview feature when processing URLs.

  - an error in the built-in XSLT templates that incorrectly handle escaped
    content.

  - an error which could be exploited to reveal random data.

  - an error when processing SVG images embedded using img tags.");

  script_tag(name:"solution", value:"Upgrade to Opera 9.63.");

  script_tag(name:"summary", value:"The host is installed with Opera web browser and is prone to
  multiple Vulnerabilities.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

operaVer = get_kb_item("Opera/Win/Version");
if(!operaVer){
  exit(0);
}

if(version_is_less(version:operaVer, test_version:"9.63")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

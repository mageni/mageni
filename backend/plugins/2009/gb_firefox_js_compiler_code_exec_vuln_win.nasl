###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_firefox_js_compiler_code_exec_vuln_win.nasl 12629 2018-12-03 15:19:43Z cfischer $
#
# Mozilla Firefox JavaScript Compiler Code Execution Vulnerability (Windows)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
#
# Upgrade to detect non vulnerable version
#   - By sharaths <sharaths@secpod.com> On 2009-07-17
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
  script_oid("1.3.6.1.4.1.25623.1.0.800843");
  script_version("$Revision: 12629 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-03 16:19:43 +0100 (Mon, 03 Dec 2018) $");
  script_tag(name:"creation_date", value:"2009-07-17 12:47:28 +0200 (Fri, 17 Jul 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-2477");
  script_bugtraq_id(35707);
  script_name("Mozilla Firefox JavaScript Compiler Code Execution Vulnerability (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/35798");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/9137");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/1868");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-41.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to execute arbitrary code which
  results in memory corruption.");

  script_tag(name:"affected", value:"Firefox version 3.5 and prior on Windows.");

  script_tag(name:"insight", value:"The flaw is due to an error when processing JavaScript code handling
  'font' HTML tags and can be exploited to cause memory corruption.");

  script_tag(name:"solution", value:"Upgrade to Firefox version 3.5.1 or later.");

  script_tag(name:"summary", value:"The host is installed with Mozilla Firefox browser and is prone
  to Remote Code Execution vulnerability.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

ffVer = get_kb_item("Firefox/Win/Ver");
if(!ffVer){
  exit(0);
}

if(version_is_less(version:ffVer, test_version:"3.5.1")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

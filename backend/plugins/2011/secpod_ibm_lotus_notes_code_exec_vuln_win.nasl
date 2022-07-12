###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ibm_lotus_notes_code_exec_vuln_win.nasl 12006 2018-10-22 07:42:16Z mmartin $
#
# IBM Lotus Notes 'cai' URI and iCal Remote Code Execution Vulnerabilities (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod  http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902298");
  script_version("$Revision: 12006 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-22 09:42:16 +0200 (Mon, 22 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-03-25 15:52:06 +0100 (Fri, 25 Mar 2011)");
  script_cve_id("CVE-2011-0912");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("IBM Lotus Notes 'cai' URI and iCal Remote Code Execution Vulnerabilities (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/43222");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/0295");
  script_xref(name:"URL", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21461514");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("General");
  script_dependencies("secpod_ibm_lotus_notes_detect_win.nasl");
  script_mandatory_keys("IBM/LotusNotes/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code in the
  context of the user running the application.");
  script_tag(name:"affected", value:"IBM Lotus Notes Version 8.0.x before 8.0.2 FP6 and 8.5.x before 8.5.1 FP5 on windows");
  script_tag(name:"insight", value:"The flaws are due to:

  - An input validation error when processing the '--launcher.library' switch
    within a 'cai:' URI, which could allow attackers to load a malicious
    library.

  - A buffer overflow error related to 'iCal', which could be exploited by
    attackers to execute arbitrary code.");
  script_tag(name:"solution", value:"Upgrade to IBM Lotus Notes 8.0.2 FP6 or 8.5.1 FP5");
  script_tag(name:"summary", value:"This host has IBM Lotus Notes installed and is prone to remote code
  execution vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.ibm.com/software/lotus/products/notes/");
  exit(0);
}


include("version_func.inc");

lotusVer = get_kb_item("IBM/LotusNotes/Win/Ver");
if(!lotusVer){
  exit(0);
}

if(lotusVer =~ "8.0")
{
  if(version_is_less(version:lotusVer, test_version:"8.0.2.6"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

if(lotusVer =~ "8.5")
{
  if(version_is_less(version:lotusVer, test_version:"8.5.1.5")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}

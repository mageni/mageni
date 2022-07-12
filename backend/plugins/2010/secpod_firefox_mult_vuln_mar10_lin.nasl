###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_firefox_mult_vuln_mar10_lin.nasl 12653 2018-12-04 15:31:25Z cfischer $
#
# Firefox Multiple Vulnerabilities Mar-10 (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902146");
  script_version("$Revision: 12653 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-04 16:31:25 +0100 (Tue, 04 Dec 2018) $");
  script_tag(name:"creation_date", value:"2010-03-30 16:15:33 +0200 (Tue, 30 Mar 2010)");
  script_cve_id("CVE-2010-0164", "CVE-2010-0165", "CVE-2010-0170", "CVE-2010-0172");
  script_bugtraq_id(38918);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Firefox Multiple Vulnerabilities Mar-10 (Linux)");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=547143");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-09.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-10.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-11.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("Firefox/Linux/Ver");
  script_tag(name:"impact", value:"Successful exploitation allows attackers to cause Denial of Service and conduct
  cross site scripting attacks.");
  script_tag(name:"affected", value:"Firefox version 3.6 before 3.6.2 on Linux.");
  script_tag(name:"insight", value:"The multiple flaws are due to:

  - An use-after-free error in the 'imgContainer::InternalAddFrameHelper'
     function in 'src/imgContainer.cpp' in 'libpr0n', allows to cause denial of service
     via a multipart/x-mixed-replace animation.

  - An error in 'TraceRecorder::traverseScopeChain()' within 'js/src/jstracer.cpp'
     allows to cause a memory corruption via vectors involving certain indirect
     calls to the JavaScript eval function.

  - An error while offering plugins in expected window which allows to conduct
     cross site scripting attacks via vectors that are specific to each affected
     plugin.");
  script_tag(name:"solution", value:"Upgrade to Firefox version 3.6.2.");
  script_tag(name:"summary", value:"The host is installed with firefox browser and is prone to multiple
  vulnerabilities.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.mozilla.com/en-US/firefox/all.html");
  exit(0);
}


include("version_func.inc");

ffVer = get_kb_item("Firefox/Linux/Ver");
if(isnull(ffVer)){
  exit(0);
}

if(version_in_range(version:ffVer, test_version:"3.6", test_version2:"3.6.1")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

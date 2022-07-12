###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Silverlight Code Execution Vulnerabilities - 2681578 (Mac OS X)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902678");
  script_version("2019-05-03T12:31:27+0000");
  script_cve_id("CVE-2011-3402", "CVE-2012-0159");
  script_bugtraq_id(50462, 53335);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2012-05-14 13:06:50 +0530 (Mon, 14 May 2012)");
  script_name("Microsoft Silverlight Code Execution Vulnerabilities - 2681578 (Mac OS X)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/49121");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2681578");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2690729");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1027048");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/bulletin/ms12-034");

  script_copyright("Copyright (C) 2012 SecPod");
  script_category(ACT_GATHER_INFO);
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gb_ms_silverlight_detect_macosx.nasl");
  script_mandatory_keys("MS/Silverlight/MacOSX/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code by
  tricking a user into opening a specially crafted file.");
  script_tag(name:"affected", value:"Microsoft Silverlight versions 4 and 5");
  script_tag(name:"insight", value:"The flaws are due to an error exists when parsing TrueType fonts.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS12-034.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/bulletin/MS12-034");
  exit(0);
}


include("version_func.inc");

slightVer = get_kb_item("MS/Silverlight/MacOSX/Ver");
if(!slightVer){
  exit(0);
}

if(version_in_range(version: slightVer, test_version:"4.0", test_version2:"4.1.10328")||
   version_in_range(version: slightVer, test_version:"5.0", test_version2:"5.1.10410")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_winrar_mult_vuln.nasl 12673 2018-12-05 15:02:55Z cfischer $
#
# WinRAR Multiple Unspecified Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.901022");
  script_version("$Revision: 12673 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-05 16:02:55 +0100 (Wed, 05 Dec 2018) $");
  script_tag(name:"creation_date", value:"2009-09-16 15:34:19 +0200 (Wed, 16 Sep 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-7144");
  script_name("WinRAR Multiple Unspecified Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/29407");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/41251");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2008/0916/references");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("General");
  script_dependencies("secpod_winrar_detect.nasl");
  script_mandatory_keys("WinRAR/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to cause heap corruptions
  or stack-based buffer overflows or execution of arbitrary code.");
  script_tag(name:"affected", value:"WinRAR versions prior to 3.71");
  script_tag(name:"insight", value:"The flaw is due to unspecified errors in the processing of several
  archive files.");
  script_tag(name:"solution", value:"Upgrade to WinRAR version 3.71 or later.");
  script_tag(name:"summary", value:"This host has WinRAR installed and is prone to Multiple
  Vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.rarlab.com/download.htm");
  exit(0);
}


include("version_func.inc");

winrarVer = get_kb_item("WinRAR/Ver");
if(winrarVer != NULL)
{
  if(version_is_less(version:winrarVer, test_version:"3.71")){
     security_message( port: 0, data: "The target host was found to be vulnerable" );
   }
}

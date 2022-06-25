###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_apple_safari_pdf_js_rest_bypass_vuln.nasl 12631 2018-12-03 15:32:54Z cfischer $
#
# Apple Safari PDF Javascript Security Bypass Bypass Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900637");
  script_version("$Revision: 12631 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-03 16:32:54 +0100 (Mon, 03 Dec 2018) $");
  script_tag(name:"creation_date", value:"2009-05-19 08:03:45 +0200 (Tue, 19 May 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1600");
  script_name("Apple Safari PDF Javascript Security Bypass Bypass Vulnerability");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/503183/100/0/threaded");
  script_xref(name:"URL", value:"http://secniche.org/papers/SNS_09_03_PDF_Silent_Form_Re_Purp_Attack.pdf");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_apple_safari_detect_win_900003.nasl");
  script_mandatory_keys("AppleSafari/Version");
  script_tag(name:"affected", value:"Apple Safari 4.28.17.0 and prior on Windows.");
  script_tag(name:"insight", value:"An error in Adobe Acrobat JavaScript protocol handler in the context of browser
  when a PDF file is opened in it via execute DOM calls in response to a
  javascript: URI.");
  script_tag(name:"solution", value:"Upgrade to Apple Safari version 5.0 or later");
  script_tag(name:"summary", value:"The host is installed with Opera Web Browser and is prone to PDF
  Javascript Security Bypass Vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will let attacker to execute arbitrary code result in
  spoof URLs, bypass the security restriction, XSS, Memory corruption, phishing
  attacks and steal generic information from website.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.apple.com/support/downloads");
  exit(0);
}


include("version_func.inc");

safariVer = get_kb_item("AppleSafari/Version");
if(safariVer == NULL){
  exit(0);
}

if(version_is_less_equal(version:safariVer, test_version:"4.28.17.0")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

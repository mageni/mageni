######################################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_nss_priv_escalation_vuln_macosx.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Google Chrome Mozilla Network Security Services Privilege Escalation Vulnerability (Mac OS X)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802339");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-11-03 12:22:48 +0100 (Thu, 03 Nov 2011)");
  script_cve_id("CVE-2011-3640");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Google Chrome Mozilla Network Security Services Privilege Escalation Vulnerability (Mac OS X)");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=641052");
  script_xref(name:"URL", value:"http://code.google.com/p/chromium/issues/detail?id=97426");
  script_xref(name:"URL", value:"http://blog.acrossecurity.com/2011/10/google-chrome-pkcs11txt-file-planting.html");

  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("GoogleChrome/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation will let the local attacker to execute arbitrary
  code with an elevated privileges.");
  script_tag(name:"affected", value:"Google Chrome version 16.0.912.21 and prior on Mac OS X");
  script_tag(name:"insight", value:"The flaw is due to an error in the Mozilla Network Security Services
  (NSS) library, which can be exploited by sending Trojan horse pkcs11.txt
  file in a top-level directory.");
  script_tag(name:"solution", value:"Upgrade to the Google Chrome 17 or later.");
  script_tag(name:"summary", value:"The host is installed with Google Chrome and is prone to privilege
  escalation vulnerability");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.google.com/chrome");
  exit(0);
}


include("version_func.inc");

chromeVer = get_kb_item("GoogleChrome/MacOSX/Version");
if(!chromeVer){
  exit(0);
}

if(version_is_less_equal(version:chromeVer, test_version:"16.0.912.21")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

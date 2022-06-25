###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_google_chrome_mult_vuln_win01.nasl 14331 2019-03-19 14:03:05Z jschulte $
#
# Google Chrome Multiple Vulnerabilities - (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.902121");
  script_version("$Revision: 14331 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 15:03:05 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-02-22 13:34:53 +0100 (Mon, 22 Feb 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-0650", "CVE-2010-0651", "CVE-2010-0655", "CVE-2010-0656",
                "CVE-2010-0657", "CVE-2010-0658", "CVE-2010-0659", "CVE-2010-0660",
                "CVE-2010-0661", "CVE-2010-0662", "CVE-2010-0663", "CVE-2010-0664");
  script_name("Google Chrome Multiple Vulnerabilities - (Windows)");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2010/Jan/1023506.html");
  script_xref(name:"URL", value:"http://code.google.com/p/chromium/issues/detail?id=9877");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2010/01/stable-channel-update_25.html");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will let the attacker bypass restrictions, disclose
  sensitive information or compromise a vulnerable system.");
  script_tag(name:"affected", value:"Google Chrome version prior to 4.0.249.78");
  script_tag(name:"insight", value:"For more information about vulnerabilities on Google Chrome, refer to the
  links mentioned in References section.");
  script_tag(name:"solution", value:"Upgrade to version 4.0.249.78 or later");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"This host is installed with Google Chrome and is prone to multiple
  vulnerabilities.");
  exit(0);
}


include("version_func.inc");

chromeVer = get_kb_item("GoogleChrome/Win/Ver");
if(!chromeVer){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"4.0.249.78")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}

exit(99);

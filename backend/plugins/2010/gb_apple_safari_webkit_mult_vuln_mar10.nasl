###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_safari_webkit_mult_vuln_mar10.nasl 12653 2018-12-04 15:31:25Z cfischer $
#
# Apple Safari Webkit Multiple Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800493");
  script_version("$Revision: 12653 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-04 16:31:25 +0100 (Tue, 04 Dec 2018) $");
  script_tag(name:"creation_date", value:"2010-03-18 15:44:57 +0100 (Thu, 18 Mar 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-0040", "CVE-2010-0041", "CVE-2010-0042", "CVE-2010-0043",
                "CVE-2010-0044", "CVE-2010-0045", "CVE-2010-0046", "CVE-2010-0047",
                "CVE-2010-0048", "CVE-2010-0049", "CVE-2010-0050", "CVE-2010-0051",
                "CVE-2010-0052", "CVE-2010-0053", "CVE-2010-0054");
  script_bugtraq_id(38674, 38676, 38677, 38673, 38675, 38683, 38684, 38687, 38688,
                    38689, 38685, 38692, 38686, 38690, 38691);
  script_name("Apple Safari Webkit Multiple Vulnerabilities");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT4070");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2010/Mar/msg00000.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_apple_safari_detect_win_900003.nasl");
  script_mandatory_keys("AppleSafari/Version");
  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary code, bypass
  security restrictions, sensitive information disclosure, and can cause other
  attacks.");
  script_tag(name:"affected", value:"Apple Safari version prior to 4.0.5 (5.31.22.7) on Windows.");
  script_tag(name:"insight", value:"For more information about vulnerabilities on Apple Safari, go through the links
  mentioned in references.");
  script_tag(name:"solution", value:"Upgrade to Apple Safari version 4.0.5.");
  script_tag(name:"summary", value:"This host is installed with Apple Safari Web Browser and is prone to
  to multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.apple.com/support/downloads");
  exit(0);
}


include("version_func.inc");

safariVer = get_kb_item("AppleSafari/Version");
if(!safariVer){
  exit(0);
}

if(version_is_less(version:safariVer, test_version:"5.31.22.7")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_apple_safari_mult_vuln_jul10.nasl 12653 2018-12-04 15:31:25Z cfischer $
#
# Apple Safari Multiple Vulnerabilities - July 10
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.901138");
  script_version("$Revision: 12653 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-04 16:31:25 +0100 (Tue, 04 Dec 2018) $");
  script_tag(name:"creation_date", value:"2010-08-02 12:38:17 +0200 (Mon, 02 Aug 2010)");
  script_bugtraq_id(42020);
  script_cve_id("CVE-2010-1778", "CVE-2010-1780", "CVE-2010-1783", "CVE-2010-1782",
                "CVE-2010-1785", "CVE-2010-1784", "CVE-2010-1786", "CVE-2010-1788",
                "CVE-2010-1787", "CVE-2010-1790", "CVE-2010-1789", "CVE-2010-1792",
                "CVE-2010-1791", "CVE-2010-1793", "CVE-2010-1796");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Apple Safari Multiple Vulnerabilities - July 10");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT4276");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2010/Jul/msg00001.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("General");
  script_dependencies("secpod_apple_safari_detect_win_900003.nasl");
  script_mandatory_keys("AppleSafari/Version");
  script_tag(name:"impact", value:"Successful exploitation may results in information disclosure, remote code
  execution, denial of service, or other consequences.");
  script_tag(name:"affected", value:"Apple Safari version prior to 5.0.1 (5.33.17.8) on Windows.");
  script_tag(name:"insight", value:"For more information about vulnerabilities on Apple Safari, go through the
  links mentioned in references.");
  script_tag(name:"solution", value:"Upgrade to Apple Safari version 5.0.1 or later.");
  script_tag(name:"summary", value:"This host is installed with Apple Safari Web Browser and is prone
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

if(version_is_less(version:safariVer, test_version:"5.33.17.8")) {
   security_message( port: 0, data: "The target host was found to be vulnerable" );
}


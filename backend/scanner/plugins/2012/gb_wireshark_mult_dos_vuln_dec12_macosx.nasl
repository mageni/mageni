###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_mult_dos_vuln_dec12_macosx.nasl 11888 2018-10-12 15:27:49Z cfischer $
#
# Wireshark Multiple Dissector Multiple DoS Vulnerabilities - Dec12 (Mac OS X)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803069");
  script_version("$Revision: 11888 $");
  script_cve_id("CVE-2012-6053", "CVE-2012-6062", "CVE-2012-6061", "CVE-2012-6060",
                "CVE-2012-6059", "CVE-2012-6058");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 17:27:49 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-12-07 18:39:59 +0530 (Fri, 07 Dec 2012)");
  script_name("Wireshark Multiple Dissector Multiple DoS Vulnerabilities - Dec12 (Mac OS X)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/51422");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2012-31.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2012-35.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2012-36.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2012-37.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2012-38.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2012-40.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_macosx.nasl");
  script_mandatory_keys("Wireshark/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to denial of service or
  to consume excessive CPU resources.");
  script_tag(name:"affected", value:"Wireshark 1.6.x before 1.6.12, 1.8.x before 1.8.4 on Mac OS X");
  script_tag(name:"insight", value:"The flaws are due to an errors in USB, RTCP, WTP, iSCSI, ISAKMP and ICMPv6
  dissectors, which can be exploited to cause a crash.");
  script_tag(name:"solution", value:"Upgrade to the Wireshark version 1.6.12 or 1.8.4 or later.");
  script_tag(name:"summary", value:"This host is installed with Wireshark and is prone to multiple
  denial of service vulnerabilities.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.wireshark.org/download");
  exit(0);
}


include("version_func.inc");

sharkVer = get_kb_item("Wireshark/MacOSX/Version");
if(!sharkVer){
  exit(0);
}

if(version_in_range(version:sharkVer, test_version:"1.6.0", test_version2:"1.6.11") ||
   version_in_range(version:sharkVer, test_version:"1.8.0", test_version2:"1.8.3")) {
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

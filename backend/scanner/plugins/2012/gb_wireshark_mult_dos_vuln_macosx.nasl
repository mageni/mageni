###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_mult_dos_vuln_macosx.nasl 11857 2018-10-12 08:25:16Z cfischer $
#
# Wireshark Multiple Denial of Service Vulnerabilities (Mac OS X)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802763");
  script_version("$Revision: 11857 $");
  script_cve_id("CVE-2012-1596", "CVE-2012-1595", "CVE-2012-1593");
  script_bugtraq_id(52736, 52737, 52735);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 10:25:16 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-04-24 15:17:23 +0530 (Tue, 24 Apr 2012)");
  script_name("Wireshark Multiple Denial of Service Vulnerabilities (Mac OS X)");


  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_macosx.nasl");
  script_mandatory_keys("Wireshark/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause a denial of
  service.");
  script_tag(name:"affected", value:"Wireshark versions 1.4.x before 1.4.12 and 1.6.x before 1.6.6 on Mac OS X");
  script_tag(name:"insight", value:"The flaws are due to

  - A NULL pointer dereference error in the ANSI A dissector can be exploited
    to cause a crash via a specially crafted packet.

  - An error in the MP2T dissector when allocating memory can be exploited to
    cause a crash via a specially crafted packet.

  - An error exists in the pcap and pcap-ng file parsers when reading ERF data
    and can cause a crash via a specially crafted trace file.");
  script_tag(name:"solution", value:"Upgrade to the Wireshark version 1.4.12, 1.6.6 or later.");
  script_tag(name:"summary", value:"This host is installed with Wireshark and is prone to multiple
  denial of service vulnerabilities.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2012-07.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2012-06.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2012-04.html");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2012/03/28/13");
  script_xref(name:"URL", value:"http://anonsvn.wireshark.org/viewvc?view=revision&revision=41001");
  script_xref(name:"URL", value:"http://www.wireshark.org/download");
  exit(0);
}


include("version_func.inc");

sharkVer = get_kb_item("Wireshark/MacOSX/Version");
if(!sharkVer){
  exit(0);
}

if(version_in_range (version:sharkVer, test_version:"1.4.0", test_version2:"1.4.11") ||
   version_in_range (version:sharkVer, test_version:"1.6.0", test_version2:"1.6.5")) {
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

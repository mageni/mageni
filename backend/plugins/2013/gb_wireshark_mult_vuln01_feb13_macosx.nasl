###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_mult_vuln01_feb13_macosx.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# Wireshark Multiple Vulnerabilities(01) - Feb2013 (Mac OS X)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803166");
  script_version("$Revision: 11865 $");
  script_cve_id("CVE-2013-1572", "CVE-2013-1573", "CVE-2013-1574", "CVE-2013-1575",
                "CVE-2013-1576", "CVE-2013-1577", "CVE-2013-1578", "CVE-2013-1579",
                "CVE-2013-1580", "CVE-2013-1581", "CVE-2013-1582", "CVE-2013-1583",
                "CVE-2013-1584", "CVE-2013-1585", "CVE-2013-1586", "CVE-2013-1587",
                "CVE-2013-1588", "CVE-2013-1589", "CVE-2013-1590");
  script_bugtraq_id(57616);
  script_tag(name:"cvss_base", value:"2.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-02-04 19:46:29 +0530 (Mon, 04 Feb 2013)");
  script_name("Wireshark Multiple Vulnerabilities(01) - Feb2013 (Mac OS X)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/51968");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2013-01.html");
  script_xref(name:"URL", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=8037");
  script_xref(name:"URL", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=8038");
  script_xref(name:"URL", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=8040");
  script_xref(name:"URL", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=8041");
  script_xref(name:"URL", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=8042");
  script_xref(name:"URL", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=8043");
  script_xref(name:"URL", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=8198");
  script_xref(name:"URL", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=8222");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_wireshark_detect_macosx.nasl");
  script_mandatory_keys("Wireshark/MacOSX/Version");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to crash affected
  application or to consume excessive CPU resources.");

  script_tag(name:"affected", value:"Wireshark 1.6.x before 1.6.13 and 1.8.x before 1.8.5 on Mac OS X");

  script_tag(name:"insight", value:"The flaws are due to

  - Errors in the Bluetooth HCI, CSN.1, DCP-ETSI DOCSIS CM-STAUS, IEEE 802.3
    Slow Protocols, MPLS, R3, RTPS, SDP, and SIP dissectors can be exploited
    to trigger infinite loops and consume CPU resources via specially crafted
    packets.

  - An error in the CLNP, DTN, MS-MMC, DTLS, DCP-ETSI, NTLMSSP and ROHC
    dissector when processing certain packets can be exploited to cause a
    crash via a specially crafted packet.

  - An error in the dissection engine when processing certain packets can be
    exploited to cause a crash via a specially crafted packet.");

  script_tag(name:"solution", value:"Upgrade to the Wireshark version 1.6.13, 1.8.5 or later.");

  script_tag(name:"summary", value:"This host is installed with Wireshark and is prone to multiple
  vulnerabilities.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.wireshark.org/download");
  exit(0);
}

include("version_func.inc");

sharkVer = get_kb_item("Wireshark/MacOSX/Version");
if(!sharkVer && sharkVer !~ "^1\.[68]"){
  exit(0);
}

if(version_in_range(version:sharkVer, test_version:"1.8.0", test_version2:"1.8.4") ||
   version_in_range(version:sharkVer, test_version:"1.6.0", test_version2:"1.6.12")) {
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

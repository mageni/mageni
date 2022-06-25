###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_mult_vuln_win_may11.nasl 11987 2018-10-19 11:05:52Z mmartin $
#
# Wireshark Denial of Service and Buffer Overflow Vulnerabilities (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.801786");
  script_version("$Revision: 11987 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 13:05:52 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-05-16 15:25:30 +0200 (Mon, 16 May 2011)");
  script_cve_id("CVE-2011-1591", "CVE-2011-1592");
  script_bugtraq_id(47392);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Wireshark Denial of Service and Buffer Overflow Vulnerabilities (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/44172");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/66834");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/1022");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2011-06.html");

  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_family("General");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_mandatory_keys("Wireshark/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to overflow a buffer and
  execute arbitrary code on the system or cause the application to crash.");
  script_tag(name:"affected", value:"Wireshark version 1.4.0 through 1.4.4");
  script_tag(name:"insight", value:"The flaws are due to:

  - a buffer overflow error in the 'DECT' dissector when processing malformed
    data, which could allow code execution via malformed packets or a malicious
    PCAP file.

  - an error in the 'NFS' dissector when processing malformed data, which could
    be exploited to crash an affected application.");
  script_tag(name:"solution", value:"Upgrade to the Wireshark version 1.4.5 or later.");
  script_tag(name:"summary", value:"The host is installed with Wireshark and is prone to Denial of
  Service and buffer overflow vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.wireshark.org/download.html");
  exit(0);
}


include("version_func.inc");

wiresharkVer = get_kb_item("Wireshark/Win/Ver");
if(!wiresharkVer){
  exit(0);
}

if(version_in_range(version:wiresharkVer, test_version:"1.4.0", test_version2:"1.4.4")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

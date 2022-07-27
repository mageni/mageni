###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_mult_vuln_macosx.nasl 11857 2018-10-12 08:25:16Z cfischer $
#
# Wireshark Multiple Vulnerabilities (Mac OS X)
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
  script_oid("1.3.6.1.4.1.25623.1.0.802764");
  script_version("$Revision: 11857 $");
  script_cve_id("CVE-2012-0068", "CVE-2012-0067", "CVE-2012-0066", "CVE-2012-0043",
                "CVE-2012-0042", "CVE-2012-0041");
  script_bugtraq_id(51710, 51368);
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 10:25:16 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-04-24 15:23:18 +0530 (Tue, 24 Apr 2012)");
  script_name("Wireshark Multiple Vulnerabilities (Mac OS X)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/47494/");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2012-01.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_wireshark_detect_macosx.nasl");
  script_mandatory_keys("Wireshark/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary code
  or cause a denial of service.");
  script_tag(name:"affected", value:"Wireshark versions 1.4.x before 1.4.11 and 1.6.x before 1.6.5 on Mac OS X");
  script_tag(name:"insight", value:"The flaws are due to

  - NULL pointer dereference errors when reading certain packet information
    can be exploited to cause a crash.

  - An error within the RLC dissector can be exploited to cause a buffer
    overflow via a specially crafted RLC packet capture file.

  - An error within the 'lanalyzer_read()' function (wiretap/lanalyzer.c) when
    parsing LANalyzer files can be exploited to cause a heap-based buffer
    underflow.");
  script_tag(name:"solution", value:"Upgrade to the Wireshark version 1.4.11, 1.6.5 or later.");
  script_tag(name:"summary", value:"This host is installed with Wireshark and is prone to multiple
  vulnerabilities.");
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

if(version_in_range(version:sharkVer, test_version:"1.4.0", test_version2:"1.4.10") ||
   version_in_range(version:sharkVer, test_version:"1.6.0", test_version2:"1.6.4")) {
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

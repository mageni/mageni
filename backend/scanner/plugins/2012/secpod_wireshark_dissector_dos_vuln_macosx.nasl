###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_wireshark_dissector_dos_vuln_macosx.nasl 11857 2018-10-12 08:25:16Z cfischer $
#
# Wireshark X.509if Dissector Denial of Service Vulnerability (Mac OS X)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.903022");
  script_version("$Revision: 11857 $");
  script_cve_id("CVE-2011-1590");
  script_bugtraq_id(47392);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 10:25:16 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-04-26 10:21:42 +0530 (Thu, 26 Apr 2012)");
  script_name("Wireshark X.509if Dissector Denial of Service Vulnerability (Mac OS X)");


  script_copyright("Copyright (C) 2012 SecPod");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_macosx.nasl");
  script_mandatory_keys("Wireshark/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to cause a denial of service
  via crafted '.pcap' file.");
  script_tag(name:"affected", value:"Wireshark version 1.2.0 through 1.2.15
  Wireshark version 1.4.0 through 1.4.4");
  script_tag(name:"insight", value:"The flaw is caused by an error in the 'X.509if' dissector when processing
  malformed data, which could be exploited to crash an affected application.");
  script_tag(name:"solution", value:"Upgrade to the Wireshark version 1.4.5 or 1.2.16 or later.");
  script_tag(name:"summary", value:"This host is installed with Wireshark and is prone to denial of
  service vulnerability.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1025388");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/1022");
  script_xref(name:"URL", value:"http://www.wireshark.org/download.html");
  exit(0);
}


include("version_func.inc");

wiresharkVer = get_kb_item("Wireshark/MacOSX/Version");
if(!wiresharkVer){
  exit(0);
}

if(version_in_range(version:wiresharkVer, test_version:"1.2.0", test_version2:"1.2.15")||
   version_in_range(version:wiresharkVer, test_version:"1.4.0", test_version2:"1.4.4")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

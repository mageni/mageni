###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_ieee_dissector_dos_vuln_win.nasl 11857 2018-10-12 08:25:16Z cfischer $
#
# Wireshark IEEE 802.11 Dissector Denial of Service Vulnerability (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.802760");
  script_version("$Revision: 11857 $");
  script_cve_id("CVE-2012-1594");
  script_bugtraq_id(52738);
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 10:25:16 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-04-23 18:08:49 +0530 (Mon, 23 Apr 2012)");
  script_name("Wireshark IEEE 802.11 Dissector Denial of Service Vulnerability (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/48548/");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2012-05.html");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2012/03/28/13");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_mandatory_keys("Wireshark/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause a denial of
  service.");
  script_tag(name:"affected", value:"Wireshark versions 1.6.x before 1.6.6 on Windows");
  script_tag(name:"insight", value:"The flaw is due to an error in the IEEE 802.11 dissector can be
  exploited to cause an infinite loop via a specially crafted packet.");
  script_tag(name:"solution", value:"Upgrade to the Wireshark version 1.6.6 or later.");
  script_tag(name:"summary", value:"This host is installed with Wireshark and is prone to denial of
  service vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.wireshark.org/download");
  exit(0);
}


include("version_func.inc");

sharkVer = get_kb_item("Wireshark/Win/Ver");
if(!sharkVer){
  exit(0);
}

if(version_in_range(version:sharkVer, test_version:"1.6.0", test_version2:"1.6.5")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_ppp_n_nfs_dos_vuln_win.nasl 11857 2018-10-12 08:25:16Z cfischer $
#
# Wireshark PPP And NFS Dissector Denial of Service Vulnerabilities (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.802898");
  script_version("$Revision: 11857 $");
  script_cve_id("CVE-2012-4048", "CVE-2012-4049");
  script_bugtraq_id(54649);
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 10:25:16 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-07-27 10:00:50 +0530 (Fri, 27 Jul 2012)");
  script_name("Wireshark PPP And NFS Dissector Denial of Service Vulnerabilities (Windows)");


  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_mandatory_keys("Wireshark/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause a denial of
  service.");
  script_tag(name:"affected", value:"Wireshark versions 1.4.x before 1.4.14,
  1.6.x before 1.6.9 and 1.8.x before 1.8.1 on Windows");
  script_tag(name:"insight", value:"Erros within the PPP and 'epan/dissectors/packet-nfs.c' in the NFS
  dissector can be exploited to cause a crash via specially crafted packets.");
  script_tag(name:"solution", value:"Upgrade to the Wireshark version 1.4.14, 1.6.9, 1.8.1 or later.");
  script_tag(name:"summary", value:"This host is installed with Wireshark and is prone to denial
  of service vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://secunia.com/advisories/49971");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1027293");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2012-11.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2012-12.html");
  script_xref(name:"URL", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=7436");
  script_xref(name:"URL", value:"http://anonsvn.wireshark.org/viewvc/trunk/epan/dissectors/packet-nfs.c?r1=43576&r2=43575&pathrev=43576");
  script_xref(name:"URL", value:"http://www.wireshark.org/download");
  exit(0);
}


include("version_func.inc");

sharkVer = get_kb_item("Wireshark/Win/Ver");
if(!sharkVer){
  exit(0);
}

if(version_in_range(version: sharkVer, test_version:"1.4.0", test_version2:"1.4.13") ||
   version_in_range(version: sharkVer, test_version:"1.6.0", test_version2:"1.6.8") ||
   version_is_equal(version: sharkVer, test_version:"1.8.0")) {
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

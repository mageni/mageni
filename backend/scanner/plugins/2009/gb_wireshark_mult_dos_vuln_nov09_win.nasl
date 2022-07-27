###############################################################################
# OpenVAS Vulnerability Test
#
# Wireshark Multiple Denial Of Service Vulnerabilities - Nov09 (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801032");
  script_version("2019-04-29T15:08:03+0000");
  script_tag(name:"last_modification", value:"2019-04-29 15:08:03 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2009-11-04 07:03:36 +0100 (Wed, 04 Nov 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-3549", "CVE-2009-3551");
  script_bugtraq_id(36846);
  script_name("Wireshark Multiple Denial Of Service Vulnerabilities - Nov09 (Windows)");

  script_xref(name:"URL", value:"http://secunia.com/advisories/37175");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/3061");
  script_xref(name:"URL", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=3689");
  script_xref(name:"URL", value:"http://www.wireshark.org/docs/relnotes/wireshark-1.2.3.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2009-07.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_mandatory_keys("Wireshark/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation could result in Denial of service condition.");
  script_tag(name:"affected", value:"Wireshark version 1.2.0 to 1.2.2 on Windows.");
  script_tag(name:"insight", value:"- An alignment error within the 'dissect_paltalk()' function in
    epan/dissectors/packet-paltalk.c of the Paltalk dissector that can be
    exploited to cause a crash.

  - An off-by-one error within the 'dissect_negprot_response()' function in
    epan/dissectors/packet-smb.c of the SMB dissector that can be exploited to
    cause a crash.");
  script_tag(name:"summary", value:"This host is installed with Wireshark and is prone to multiple
  Denial of Service vulnerabilities.");
  script_tag(name:"solution", value:"Upgrade to Wireshark 1.2.3.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

sharkVer = get_kb_item("Wireshark/Win/Ver");
if(!sharkVer)
  exit(0);

if(version_in_range(version:sharkVer, test_version:"1.2.0", test_version2:"1.2.2")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

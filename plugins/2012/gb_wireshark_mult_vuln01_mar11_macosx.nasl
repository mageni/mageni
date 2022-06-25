###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_mult_vuln01_mar11_macosx.nasl 11818 2018-10-10 11:35:42Z asteins $
#
# Wireshark Multiple Vulnerabilities-01 March 11 (Mac OS X)
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
  script_oid("1.3.6.1.4.1.25623.1.0.802903");
  script_version("$Revision: 11818 $");
  script_cve_id("CVE-2011-1140", "CVE-2011-1141");
  script_bugtraq_id(46626);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-10 13:35:42 +0200 (Wed, 10 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-06-27 15:40:58 +0530 (Wed, 27 Jun 2012)");
  script_name("Wireshark Multiple Vulnerabilities-01 March 11 (Mac OS X)");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2011-03.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2011-04.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/docs/relnotes/wireshark-1.4.4.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/docs/relnotes/wireshark-1.2.15.html");

  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_wireshark_detect_macosx.nasl");
  script_mandatory_keys("Wireshark/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to cause a denial of
  service.");
  script_tag(name:"affected", value:"Wireshark 1.0.x
  Wireshark version 1.2.0 through 1.2.14
  Wireshark version 1.4.0 through 1.4.3");
  script_tag(name:"insight", value:"The flaws are due to

  - Multiple stack consumption vulnerabilities in the
    'dissect_ms_compressed_string' and 'dissect_mscldap_string functions'

  - Error in 'epan/dissectors/packet-ldap.c' which allows attackers to cause
    a denial of service via a long LDAP filter string or an LDAP filter string
    containing many elements.");
  script_tag(name:"solution", value:"Upgrade to the Wireshark version 1.4.4 or 1.2.15");
  script_tag(name:"summary", value:"The host is installed with Wireshark and is prone to multiple
  vulnerabilities.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.wireshark.org/download.html");
  exit(0);
}


include("version_func.inc");

wiresharkVer = get_kb_item("Wireshark/MacOSX/Version");
if(!wiresharkVer){
  exit(0);
}

if(version_in_range(version:wiresharkVer, test_version:"1.0", test_version2:"1.0.16")||
   version_in_range(version:wiresharkVer, test_version:"1.2.0", test_version2:"1.2.14")||
   version_in_range(version:wiresharkVer, test_version:"1.4.0", test_version2:"1.4.3")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

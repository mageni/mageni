###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_mult_vuln01_sep13_win.nasl 31865 2013-09-26 19:35:17Z sep$
#
# Wireshark Multiple Vulnerabilities-01 Sep13 (Windows)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804016");
  script_version("$Revision: 11865 $");
  script_cve_id("CVE-2013-5718", "CVE-2013-5719", "CVE-2013-5720", "CVE-2013-5721",
                "CVE-2013-5722");
  script_bugtraq_id(62315, 62318, 62319, 62320, 62321);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-09-26 19:35:17 +0530 (Thu, 26 Sep 2013)");
  script_name("Wireshark Multiple Vulnerabilities-01 Sep13 (Windows)");


  script_tag(name:"summary", value:"This host is installed with Wireshark and is prone to multiple
vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Upgrade to Wireshark version 1.8.10 or 1.10.2 or later.");
  script_tag(name:"insight", value:"Multiple flaws are due to error in,

  - ASSA R3 dissector (dissectors/packet-assa_r3.c)

  - NBAP dissector (dissectors/packet-nbap.c)

  - RTPS dissector (dissectors/packet-rtsp.c)

  - LDAP dissector (dissectors/packet-ldap.c)

  - MQ dissector (dissectors/packet-mq.c)

  - Netmon file parser (wiretap/netmon.c)");
  script_tag(name:"affected", value:"Wireshark 1.8.x before 1.8.10 and 1.10.x before 1.10.2 on Windows");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause a DoS (Denial of Service)
and potentially compromise a vulnerable system.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/54765");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2013-55.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_mandatory_keys("Wireshark/Win/Ver");
  script_xref(name:"URL", value:"http://www.wireshark.org/download");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!sharkVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(sharkVer  =~ "^(1\.(8|10))")
{
  if(version_in_range(version:sharkVer, test_version:"1.8.0", test_version2:"1.8.9")||
     version_in_range(version:sharkVer, test_version:"1.10.0", test_version2:"1.10.1"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

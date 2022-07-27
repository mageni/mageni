###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_frame_metadissector_dos_vuln_win.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# Wireshark 'Frame Metadissector' Denial of Service Vulnerability (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804665");
  script_version("$Revision: 11867 $");
  script_cve_id("CVE-2014-4020");
  script_bugtraq_id(68044);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-07-07 10:00:15 +0530 (Mon, 07 Jul 2014)");
  script_name("Wireshark 'Frame Metadissector' Denial of Service Vulnerability (Windows)");


  script_tag(name:"summary", value:"This host is installed with Wireshark and is prone to denial of service
vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Flaw is due to an error in 'dissect_frame' function in
epan/dissectors/packet-frame.c within the frame metadissector.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to conduct a DoS
(Denial of Service) attack.");
  script_tag(name:"affected", value:"Wireshark version 1.10.0 through 1.10.7 on Windows");
  script_tag(name:"solution", value:"Upgrade to Wireshark version 1.10.8 or later.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/58832");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2014-07.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
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

if(sharkVer  =~ "^(1\.10)")
{
  if(version_in_range(version:sharkVer, test_version:"1.10.0", test_version2:"1.10.7"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

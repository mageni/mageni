###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_dos_vuln02_mar15_macosx.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# Wireshark Denial-of-Service Vulnerability-02 Mar15 (Mac OS X)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805488");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2015-2191", "CVE-2015-2189", "CVE-2015-2188");
  script_bugtraq_id(72942, 72944, 72941);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-03-09 17:45:21 +0530 (Mon, 09 Mar 2015)");
  script_name("Wireshark Denial-of-Service Vulnerability-02 Mar15 (Mac OS X)");

  script_tag(name:"summary", value:"This host is installed with Wireshark
  and is prone to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw exists due to Integer overflow in
  the 'dissect_tnef' function in epan/dissectors/packet-tnef.c script in the
  TNEF dissector, Off-by-one error in the 'pcapng_read' function in
  wiretap/pcapng.c script in the pcapng file parser and a flaw in the WCP
  dissector.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct denial of service attack.");

  script_tag(name:"affected", value:"Wireshark version 1.12.x before 1.12.4
  and 1.10.x before 1.10.13 on Mac OS X");

  script_tag(name:"solution", value:"Upgrade to version 1.12.4, 1.10.3 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2015-06.html");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_wireshark_detect_macosx.nasl");
  script_mandatory_keys("Wireshark/MacOSX/Version");
  script_xref(name:"URL", value:"https://www.wireshark.org");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!wirversion = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_in_range(version:wirversion, test_version:"1.12.0", test_version2:"1.12.3"))
{
  fix = "1.12.4";
  VULN = TRUE;
}
if(version_in_range(version:wirversion, test_version:"1.10.0", test_version2:"1.10.12"))
{
  fix = "1.10.13";
  VULN = TRUE;
}
if(VULN)
{
  report = 'Installed Version: ' + wirversion + '\nFixed Version:     ' + fix + '\n';
  security_message(data:report);
  exit(0);
}



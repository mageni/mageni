###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_mult_vuln_macosx_mar17.nasl 11919 2018-10-16 09:49:19Z mmartin $
#
# Wireshark Multiple DoS Vulnerabilities Mar17 (MAC OS X)
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.809893");
  script_version("$Revision: 11919 $");
  script_cve_id("CVE-2017-6467", "CVE-2017-6468", "CVE-2017-6469", "CVE-2017-6470",
	        "CVE-2017-6471", "CVE-2017-6472", "CVE-2017-6473", "CVE-2017-6474",
                "CVE-2017-6014");
  script_bugtraq_id(96284);
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-16 11:49:19 +0200 (Tue, 16 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-03-07 13:20:20 +0530 (Tue, 07 Mar 2017)");
  script_name("Wireshark Multiple DoS Vulnerabilities Mar17 (MAC OS X)");

  script_tag(name:"summary", value:"This host is installed with Wireshark
  and is prone to multiple denial of service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - An improper validation of record sizes in 'wiretap/netscaler.c' script.

  - An improper incrementing of certain sequence value in
    'epan/dissectors/packet-rtmpt.c' script.

  - An improper validation of the relationships between lengths and offsets
    in 'wiretap/k12.c' script.

  - An error related to constraining packet lateness in
    'pan/dissectors/packet-iax2.c' script.

  - An improper validation of the capability length in
   'epan/dissectors/packet-wsp.c' script.

  - In 'epan/dissectors/packet-ldss.c' memory was not allocated for a certain
    data structure.

  - If the packet size field in a packet header is null, the offset to read from
    will not advance, causing continuous attempts to read the same zero length
    packet.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause the application to enter an infinite loop and consume
  excessive CPU resources, resulting in denial-of-service conditions.");

  script_tag(name:"affected", value:"Wireshark version 2.2.0 to 2.2.4 and
  2.0.0 to 2.0.10 on Mac OS X");

  script_tag(name:"solution", value:"Upgrade to Wireshark version 2.2.5 or
  2.0.11 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.wireshark.org/security");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-03.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-04.html");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_wireshark_detect_macosx.nasl");
  script_mandatory_keys("Wireshark/MacOSX/Version");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!wirversion = get_app_version(cpe:CPE)){
  exit(0);
}

if(wirversion =~ "^2\.")
{
  if(version_in_range(version:wirversion, test_version:"2.2.0", test_version2:"2.2.4"))
  {
    fix = "2.2.5";
    VULN = TRUE;
  }
  else if(version_in_range(version:wirversion, test_version:"2.0.0", test_version2:"2.0.10"))
  {
    fix = "2.0.11";
    VULN = TRUE;
  }

  if(VULN)
  {
    report = report_fixed_ver(installed_version:wirversion, fixed_version:fix);
    security_message(data:report);
    exit(0);
  }
}

exit(0);

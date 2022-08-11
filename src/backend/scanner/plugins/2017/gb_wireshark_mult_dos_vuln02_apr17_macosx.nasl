###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_mult_dos_vuln02_apr17_macosx.nasl 11901 2018-10-15 08:47:18Z mmartin $
#
# Wireshark Multiple DoS Vulnerabilities-02 Apr17 (Mac OS X)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.811002");
  script_version("$Revision: 11901 $");
  script_cve_id("CVE-2017-7748", "CVE-2017-7746", "CVE-2017-7747", "CVE-2017-7745",
                "CVE-2017-7705", "CVE-2017-7702", "CVE-2017-7703", "CVE-2017-7701",
                "CVE-2017-7700");
  script_bugtraq_id(97628, 97635, 97638, 97627, 97630, 97633, 97636, 97632, 97631);
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-15 10:47:18 +0200 (Mon, 15 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-04-19 15:22:16 +0530 (Wed, 19 Apr 2017)");
  script_name("Wireshark Multiple DoS Vulnerabilities-02 Apr17 (Mac OS X)");

  script_tag(name:"summary", value:"This host is installed with Wireshark
  and is prone to multiple denial-of-service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Multiple errors in WSP dissector, SLSK dissector, SIGCOMP dissector,
    RPC over RDMA dissector, WBXML dissector, BGP dissector and NetScaler file
    parser which could go into an infinite loop triggered by packet injection or
    a malformed capture file.

  - Multiple errors in PacketBB dissector and IMAP dissector triggered by packet
    injection or a malformed capture file.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause the application to crash resulting in denial-of-service
  condition.");

  script_tag(name:"affected", value:"Wireshark version 2.2.0 through 2.2.5
  and 2.0.0 through 2.0.11 on Mac OS X");

  script_tag(name:"solution", value:"Upgrade to Wireshark version 2.2.6 or
  2.2.12 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-21.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-19.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-18.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-20.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-15.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-13.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-12.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-16.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-14.html");

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
  if(version_in_range(version:wirversion, test_version:"2.2.0", test_version2:"2.2.5"))
  {
    fix = "2.2.6";
    VULN = TRUE;
  }
  else if(version_in_range(version:wirversion, test_version:"2.0.0", test_version2:"2.0.11"))
  {
    fix = "2.0.12";
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

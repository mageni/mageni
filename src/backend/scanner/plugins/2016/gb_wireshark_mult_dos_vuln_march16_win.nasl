###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_mult_dos_vuln_march16_win.nasl 11969 2018-10-18 14:53:42Z asteins $
#
# Wireshark Multiple Denial of Service Vulnerabilities March16 (Windows)
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.807446");
  script_version("$Revision: 11969 $");
  script_cve_id("CVE-2016-2528", "CVE-2016-2527", "CVE-2016-2526", "CVE-2016-2524",
                "CVE-2016-2525", "CVE-2016-2522", "CVE-2016-4415", "CVE-2016-4416",
                "CVE-2016-4419", "CVE-2016-4420");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-18 16:53:42 +0200 (Thu, 18 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-03-03 10:39:01 +0530 (Thu, 03 Mar 2016)");
  script_name("Wireshark Multiple Denial-of-Service Vulnerabilities March16 (Windows)");

  script_tag(name:"summary", value:"This host is installed with Wireshark
  and is prone to multiple denial of service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - The 'dissect_nhdr_extopt' function in 'epan/dissectors/packet-lbmc.c'
    script in the LBMC dissector does not validate length values.

  - The 'wiretap/nettrace_3gpp_32_423.c' script in the 3GPP TS 32.423 Trace
    file parser does not ensure that a '\0' character is present at the end
    of certain strings.

  - The 'epan/dissectors/packet-hiqnet.c' script in the HiQnet dissector does
    not validate the data type.

  - The 'epan/dissectors/packet-x509af.c' script in the X.509AF dissector
    mishandles the algorithm ID.

  - The 'epan/dissectors/packet-http2.c' script in the HTTP/2 dissector does
    not limit the amount of header data.

  - The 'dissect_ber_constrained_bitstring' function in 'epan/dissectors/packet-ber.c'
    script in the ASN.1 BER dissector does not verify that a certain length
    is nonzero.

  - A heap-based buffer overflow error in 'wiretap/vwr.c' script in the
    Ixia IxVeriWave file parser.

  - An error in NFS dissector.

  - 'epan/dissectors/packet-spice.c' script in the SPICE dissector in
    mishandles capability data.

  - 'epan/dissectors/packet-ieee80211.c' script in the IEEE 802.11 dissector
    mishandles the Grouping subfield.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct denial of service attack.");

  script_tag(name:"affected", value:"Wireshark version 2.0.x before 2.0.2
  on Windows");

  script_tag(name:"solution", value:"Upgrade to Wireshark version 2.0.2 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2016-08.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2016-07.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2016-06.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2016-04.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2016-05.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2016-02.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2016-13.html");

  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_mandatory_keys("Wireshark/Win/Ver");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!wirversion = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_in_range(version:wirversion, test_version:"2.0.0", test_version2:"2.0.1"))
{
  report = report_fixed_ver(installed_version:wirversion, fixed_version:"2.0.2");
  security_message(data:report);
  exit(0);
}
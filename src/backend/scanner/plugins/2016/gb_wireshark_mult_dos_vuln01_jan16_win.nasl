###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_mult_dos_vuln01_jan16_win.nasl 11969 2018-10-18 14:53:42Z asteins $
#
# Wireshark Multiple Denial-of-Service Vulnerabilities-01 January16 (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.806943");
  script_version("$Revision: 11969 $");
  script_cve_id("CVE-2015-8742", "CVE-2015-8741", "CVE-2015-8739", "CVE-2015-8740",
                "CVE-2015-8738", "CVE-2015-8736", "CVE-2015-8735", "CVE-2015-8734");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-18 16:53:42 +0200 (Thu, 18 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-01-11 11:59:19 +0530 (Mon, 11 Jan 2016)");
  script_name("Wireshark Multiple Denial-of-Service Vulnerabilities-01 January16 (Windows)");

  script_tag(name:"summary", value:"This host is installed with Wireshark
  and is prone to multiple denial of service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to

  - 'dissect_CPMSetBindings' function in 'epan/dissectors/packet-mswsp.c'
  script  in the MS-WSP dissector does not validate the column size.

  - 'dissect_ppi' function in 'epan/dissectors/packet-ppi.c' script
  in the PPI dissector does not initialize a packet-header data structure.

  - 'ipmi_fmt_udpport' function in 'epan/dissectors/packet-ipmi.c'
  script in the IPMI dissector improperly attempts to access a packet scope.

  - 'dissect_tds7_colmetadata_token' function in 'epan/dissectors/packet-tds.c'
  script in the TDS dissector does not validate the number of columns.

  - 's7comm_decode_ud_cpu_szl_subfunc' function in
  'epan/dissectors/packet-s7comm_szl_ids.c' script in the S7COMM dissector does not
  validate the list count in an SZL response.

  - 'mp2t_find_next_pcr' function in 'wiretap/mp2t.c' script
  in the MP2T file parser does not reserve memory for a trailer.

  - 'get_value' function in 'epan/dissectors/packet-btatt.c'
  script in the Bluetooth Attribute (aka BT ATT) dissector uses an incorrect
  integer data type.

  - 'dissect_nwp' function in 'epan/dissectors/packet-nwp.c'
  script in the NWP dissector mishandles the packet type.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct denial of service attack.");

  script_tag(name:"affected", value:"Wireshark version 2.0.x before 2.0.1
  on Windows");

  script_tag(name:"solution", value:"Upgrade to Wireshark version 2.0.1 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2015-60.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2015-56.html");
  script_xref(name:"URL", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=11820");
  script_xref(name:"URL", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=11817");

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

if(version_is_equal(version:wirversion, test_version:"2.0.0"))
{
  report = 'Installed Version: ' + wirversion + '\n' +
           'Fixed Version:     2.0.1 \n';
  security_message(data:report);
  exit(0);
}
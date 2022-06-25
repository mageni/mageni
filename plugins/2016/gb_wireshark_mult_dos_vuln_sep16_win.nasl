###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_mult_dos_vuln_sep16_win.nasl 12431 2018-11-20 09:21:00Z asteins $
#
# Wireshark Multiple Denial of Service Vulnerabilities September16 (Windows)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.809048");
  script_version("$Revision: 12431 $");
  script_cve_id("CVE-2016-7175", "CVE-2016-7176", "CVE-2016-7177", "CVE-2016-7178",
                "CVE-2016-7179", "CVE-2016-7180");
  script_bugtraq_id(92889);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-11-20 10:21:00 +0100 (Tue, 20 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-09-15 12:21:20 +0530 (Thu, 15 Sep 2016)");
  script_name("Wireshark Multiple Denial of Service Vulnerabilities September16 (Windows)");

  script_tag(name:"summary", value:"This host is installed with Wireshark
  and is prone to multiple denial of service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The multiple flaws are due to,

  - The 'epan/dissectors/packet-ipmi-trace.c' script in the IPMI trace dissector
    mishandles string.

  - A stack-based buffer overflow error in 'epan/dissectors/packet-catapult-dct2000.c'
    script in the Catapult DCT2000 dissector.

  - The 'epan/dissectors/packet-umts_fp.c' script in the UMTS FP dissector
    does not ensure that memory is allocated for certain data structures.

  - The 'epan/dissectors/packet-catapult-dct2000.c' script in the Catapult
    DCT2000 dissector does not restrict the number of channels.

  - The 'epan/dissectors/packet-h225.c' in the H.225 dissector calls snprintf
    with one of its input buffers as the output buffer.

  - The 'epan/dissectors/packet-qnet6.c' in the QNX6 QNET dissector mishandles
    MAC address data.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct denial of service attack.");

  script_tag(name:"affected", value:"Wireshark version 2.0.x before 2.0.6
  on Windows.");

  script_tag(name:"solution", value:"Upgrade to Wireshark version 2.0.6 or
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2016-55.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2016-54.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2016-53.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2016-51.html");

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

if(version_in_range(version:wirversion, test_version:"2.0", test_version2:"2.0.5"))
{
  report = report_fixed_ver(installed_version:wirversion, fixed_version:"2.0.6");
  security_message(data:report);
  exit(0);
}

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_mult_dos_vuln03_aug16_macosx.nasl 11938 2018-10-17 10:08:39Z asteins $
#
# Wireshark Multiple Denial of Service Vulnerabilities-03 August16 (Mac OS X)
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
  script_oid("1.3.6.1.4.1.25623.1.0.808290");
  script_version("$Revision: 11938 $");
  script_cve_id("CVE-2016-6507", "CVE-2016-6504");
  script_bugtraq_id(92167, 92164);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-17 12:08:39 +0200 (Wed, 17 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-08-09 12:20:26 +0530 (Tue, 09 Aug 2016)");
  script_name("Wireshark Multiple Denial of Service Vulnerabilities-03 August16 (Mac OS X)");

  script_tag(name:"summary", value:"This host is installed with Wireshark
  and is prone to multiple denial of service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The multiple flaws are due to,

  - An error in 'epan/dissectors/packet-mmse.c' script could cause the
    MMSE dissector to go into a long loop.

  - The 'epan/dissectors/packet-ncp2222.inc' script in the NDS dissector
    does not properly maintain a ptvc data structure.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct denial of service attack.");

  script_tag(name:"affected", value:"Wireshark version 1.12.x before 1.12.13
  on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Wireshark version 1.12.13
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2016/07/28/3");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2016-43.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2016-40.html");

  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_wireshark_detect_macosx.nasl");
  script_mandatory_keys("Wireshark/MacOSX/Version");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!wirversion = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_in_range(version:wirversion, test_version:"1.12.0", test_version2:"1.12.12"))
{
  report = report_fixed_ver(installed_version:wirversion, fixed_version:"1.12.13");
  security_message(data:report);
  exit(0);
}

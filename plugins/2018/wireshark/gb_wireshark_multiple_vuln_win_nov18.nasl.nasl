###############################################################################
# OpenVAS Vulnerability Test
#
# Wireshark Multiple Vulnerabilities-Nov18 (Windows)
#
# Authors:
# Antu Sanadi <santusecpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.814514");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-19627", "CVE-2018-19626", "CVE-2018-19625", "CVE-2018-19624",
                "CVE-2018-19623", "CVE-2018-19622");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-11-29 11:28:23 +0530 (Thu, 29 Nov 2018)");
  script_name("Wireshark Multiple Vulnerabilities-Nov18 (Windows)");

  script_tag(name:"summary", value:"This host is installed with Wireshark
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - The IxVeriWave file parser could crash,

  - The DCOM dissector could crash,

  - The Wireshark dissection engine could crash,

  - The PVFS dissector could crash,

  - The LBMPDM dissector could crash and

  - The MMSE dissector could go into an infinite loop.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attackers to cause denial of service conditions.");

  script_tag(name:"affected", value:"Wireshark versions 2.6.0 to 2.6.4 and 2.4.0 to 2.4.10 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Wireshark version 2.6.5, 2.4.11 or later. Please see the references for more information.");

  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2018-55");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2018-52");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2018-51");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2018-56");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2018-53");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2018-54");
  script_xref(name:"URL", value:"https://www.wireshark.org");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_mandatory_keys("Wireshark/Win/Ver");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
wirversion = infos['version'];
path = infos['location'];

if(version_in_range(version:wirversion, test_version:"2.6.0", test_version2:"2.6.4")){
   fix = "2.6.5";
}

else if(version_in_range(version:wirversion, test_version:"2.4.0", test_version2:"2.4.10")){
  fix = "2.4.11";
}

if(fix)
{
  report = report_fixed_ver(installed_version:wirversion, fixed_version:fix, install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);

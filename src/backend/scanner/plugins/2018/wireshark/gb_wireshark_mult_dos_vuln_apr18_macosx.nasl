###############################################################################
# OpenVAS Vulnerability Test
#
# Wireshark Multiple Denial of Service Vulnerabilities Apr18 (Mac OS X)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.813067");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-9274", "CVE-2018-9272", "CVE-2018-9273", "CVE-2018-9270",
                "CVE-2018-9271", "CVE-2018-9268", "CVE-2018-9269", "CVE-2018-9267",
                "CVE-2018-9265", "CVE-2018-9266", "CVE-2018-9263", "CVE-2018-9264",
                "CVE-2018-9262", "CVE-2018-9261", "CVE-2018-9259", "CVE-2018-9260",
                "CVE-2018-9256");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-04-05 16:18:35 +0530 (Thu, 05 Apr 2018)");
  script_name("Wireshark Multiple Denial of Service Vulnerabilities Apr18 (Mac OS X)");

  script_tag(name:"summary", value:"This host is installed with Wireshark
  and is prone to multiple denial of service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Multiple memory leak errors in 'ui/failure_message.c', 'epan/dissectors/packet-h223.c',
    'epan/dissectors/packet-pcp.c', 'epan/oids.c', 'epan/dissectors/packet-multipart.c',
    'epan/dissectors/packet-smb2.c', 'epan/dissectors/packet-lapd.c',
    'epan/dissectors/packet-isup.c', 'epan/dissectors/packet-tn3270.c',
    'epan/dissectors/packet-kerberos.c', 'epan/dissectors/packet-vlan.c',
    'epan/dissectors/packet-ieee802154.c', 'epan/dissectors/file-mp4.c' and
    'epan/dissectors/packet-lwapp.c' scripts.

  - Multiple heap-based buffer overflow errors in 'epan/dissectors/packet-nbap.c'
    and 'epan/dissectors/packet-adb.c' scripts.");

  script_tag(name:"impact", value:"Successful exploitation will make Wireshark
  crash by injecting malformed packets.");

  script_tag(name:"affected", value:"Wireshark version 2.4.0 to 2.4.5,
  2.2.0 to 2.2.13 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Wireshark version 2.4.6, 2.2.14 or later. Please see the references for more information.");

  script_xref(name:"URL", value:"https://www.wireshark.org/#download");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2018-15");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2018-16");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2018-17");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2018-18");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2018-19");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2018-24");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2018-23");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2018-20");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_wireshark_detect_macosx.nasl");
  script_mandatory_keys("Wireshark/MacOSX/Version");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
vers = infos['version'];
path = infos['location'];

if(version_in_range(version:vers, test_version:"2.2.0", test_version2:"2.2.13")) {
  fix = "2.2.14";
}

else if(version_in_range(version:vers, test_version:"2.4.0", test_version2:"2.4.5")){
  fix = "2.4.6";
}

if(fix)
{
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(data:report);
  exit(0);
}
exit(0);

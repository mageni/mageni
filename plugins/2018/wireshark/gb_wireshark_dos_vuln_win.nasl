###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_dos_vuln_win.nasl 12026 2018-10-23 08:22:54Z mmartin $
#
# Wireshark Denial of Service Vulnerability (Windows)
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
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
  script_oid("1.3.6.1.4.1.25623.1.0.112213");
  script_version("$Revision: 12026 $");
  script_cve_id("CVE-2018-6836");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-23 10:22:54 +0200 (Tue, 23 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-02-09 15:34:57 +0100 (Fri, 09 Feb 2018)");

  script_name("Wireshark Denial of Service Vulnerability (Windows)");

  script_tag(name:"summary", value:"This host is installed with Wireshark
  and is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The netmonrec_comment_destroy function in wiretap/netmon.c in Wireshark performs a free operation
  on an uninitialized memory address, which allows remote attackers to cause a denial of service (application crash) or possibly have unspecified other impact.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  will allow remote attackers to cause a denial of service or possible have unspecified other impact.");

  script_tag(name:"affected", value:"Wireshark up to and including version 2.4.4 on Windows.");

  script_tag(name:"solution", value:"Update to version 2.6.0 or later.");

  script_xref(name:"URL", value:"https://code.wireshark.org/review/#/c/25660/");
  script_xref(name:"URL", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=14397");
  script_xref(name:"URL", value:"https://code.wireshark.org/review/gitweb?p=wireshark.git;a=commit;h=28960d79cca262ac6b974f339697b299a1e28fef");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_mandatory_keys("Wireshark/Win/Ver");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) {
  exit(0);
}

vers = infos['version'];
path = infos['location'];

if(version_is_less_equal(version:vers, test_version:"2.4.4")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"2.6.0", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);

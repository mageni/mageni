###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_yara_mult_vuln_dec18.nasl 13566 2019-02-11 08:19:08Z asteins $
#
# YARA <= 3.8.1 Multiple Vulnerabilities
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2019 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112479");
  script_version("$Revision: 13566 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-11 09:19:08 +0100 (Mon, 11 Feb 2019) $");
  script_tag(name:"creation_date", value:"2019-01-08 11:36:11 +0100 (Tue, 08 Jan 2019)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:N/A:N");

  script_cve_id("CVE-2018-19974", "CVE-2018-19975", "CVE-2018-19976");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("YARA <= 3.8.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_yara_ssh_detect.nasl");
  script_mandatory_keys("yara/detected");

  script_tag(name:"summary", value:"This host is running YARA and is prone to multiple vulnerabilities.");
  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Bytecode in a specially crafted compiled rule can read uninitialized data from VM scratch memory in libyara/exec.c.
  (CVE-2018-19974)

  - Bytecode in a specially crafted compiled rule can read data from any arbitrary address in memory, in libyara/exec.c.
  Specifically, OP_COUNT can read a DWORD. (CVE-2018-19975)

  - Bytecode in a specially crafted compiled rule is exposed to information about its environment, in libyara/exec.c.
  This is a consequence of the design of the YARA virtual machine. (CVE-2018-19976)");
  script_tag(name:"impact", value:"Successfully exploiting these issues would allow attackers to discover addresses
  in the real stack (not the YARA virtual stack) and have other unspecified impact.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host");
  script_tag(name:"affected", value:"YARA through version 3.8.1.");
  script_tag(name:"solution", value:"Apply the github fix mentioned in the references to solve the issue.");

  script_xref(name:"URL", value:"https://bnbdr.github.io/posts/extracheese/");
  script_xref(name:"URL", value:"https://github.com/bnbdr/swisscheese/");
  script_xref(name:"URL", value:"https://github.com/VirusTotal/yara/issues/999");
  script_xref(name:"URL", value:"https://github.com/VirusTotal/yara/pull/1001");

  exit(0);
}

CPE = "cpe:/a:virustotal:yara";

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

vers = infos['version'];
path = infos['location'];

if(version_is_less_equal(version: vers, test_version: "3.8.1")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "Apply the referenced github fix", install_path: path);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);

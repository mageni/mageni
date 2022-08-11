###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dameware_remote_support_bof_vuln_jul13.nasl 12548 2018-11-27 11:05:01Z asteins $
#
# DameWare Remote Support Buffer Overflow Vulnerability CVE-2013-3249 (Windows)
#
# Authors:
# Michael Martin <michael.martin@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107384");
  script_version("$Revision: 12548 $");
  script_cve_id("CVE-2013-3249");
  script_bugtraq_id(61453);
  script_tag(name:"last_modification", value:"$Date: 2018-11-27 12:05:01 +0100 (Tue, 27 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-11-27 11:41:33 +0100 (Tue, 27 Nov 2018)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_name("DameWare Remote Support Buffer Overflow Vulnerability CVE-2013-3249 (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_dameware_remote_support_detect_win.nasl");
  script_mandatory_keys("dameware/remote_support/win/detected");

  script_tag(name:"summary", value:"DameWare Remote Support is prone to a local buffer overflow vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"DameWare Remote Support is vulnerable to a stack-based buffer overflow, caused by
  improper bounds checking by the DWExporter.exe when importing data");
  script_tag(name:"impact", value:"By persuading a victim to open a specially-crafted Web site, a remote attacker could
  exploit this vulnerability using the 'Add from text file' feature to overflow a buffer and execute arbitrary code on the system or cause the application to crash.");
  script_tag(name:"affected", value:"DameWare Remote Support versions 9.0.1.247, 10.0.0.372 and earlier.");
  script_tag(name:"solution", value:"Updates are available. Please contact the vendor for more information.");

  script_xref(name:"URL", value:"https://exchange.xforce.ibmcloud.com/vulnerabilities/85973");

  exit(0);
}

CPE = "cpe:/a:dameware:remote_support";

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) {
  exit (0);
}

vers = infos['version'];
path = infos['location'];

if(version_is_less_equal(version:vers, test_version:"9.0.1.247")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"See advisory", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

if(version_in_range(version:vers, test_version:"10.0.0.0", test_version2:"10.0.0.372")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"See advisory", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);

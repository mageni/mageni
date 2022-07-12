###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dlink_dir850l_mul_vuln_09_17.nasl 12444 2018-11-20 14:49:48Z cfischer $
#
# D-Link DIR-850L XSS / Backdoor / Code Execution Vulnerabilities
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

OS_CPE = "cpe:/o:d-link:dir-850l_firmware";
HW_CPE = "cpe:/h:d-link:dir-850l";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107242");
  script_cve_id("CVE-2017-14413", "CVE-2017-14414", "CVE-2017-14415", "CVE-2017-14416", "CVE-2017-14417", "CVE-2017-14418",
                "CVE-2017-14419", "CVE-2017-14420", "CVE-2017-14421", "CVE-2017-14422", "CVE-2017-14423", "CVE-2017-14424",
                "CVE-2017-14425", "CVE-2017-14426", "CVE-2017-14427", "CVE-2017-14428", "CVE-2017-14429", "CVE-2017-14430");
  script_version("$Revision: 12444 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-20 15:49:48 +0100 (Tue, 20 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-09-12 17:47:21 +0200 (Tue, 12 Sep 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("D-Link DIR-850L XSS / Backdoor / Code Execution Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dir_detect.nasl");
  script_mandatory_keys("Host/is_dlink_dir_device", "d-link/dir/hw_version");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/144056/dlink850l-xssexecxsrf.txt");
  script_xref(name:"URL", value:"http://securityaffairs.co/wordpress/62937/hacking/d-link-dir-850l-zero-day.html");
  script_xref(name:"URL", value:"http://support.dlink.com/ProductInfo.aspx?m=DIR-850L");

  script_tag(name:"summary", value:"D-Link DIR-850L suffers from cross-site scripting, access bypass, backdoor, bruteforcing,
  information disclosure, remote code execution, and denial of service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Remote attacker can execute XSS attacks, obtain the admin password, forge firmware and to
  execute remote commands.");

  script_tag(name:"affected", value:"D-Link DIR-850L Rev A1 before firmware 1.20 and B1 before 2.20.");

  script_tag(name:"solution", value:"Upgrade the D-Link DIR-850L firmware to version 1.20 for Rev. A and/or version 2.20 for Rev. B routers.

  Check the referenced vendor link for more information on how to apply the firmware.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe: OS_CPE))
  exit(0);

# cpe:/o:d-link:dir-850l_firmware:2.06
if (!fw_ver = get_app_version(cpe: OS_CPE, port: port))
  exit(0);

# cpe:/h:d-link:dir-850l:b1
if (!hw_ver = get_app_version(cpe: HW_CPE, port: port))
  exit(0);

hw_ver = toupper(hw_ver);

if (hw_ver == "A1" && version_is_less(version: fw_ver, test_version: "1.20")) {
  VULN = TRUE;
  fix  = "1.20";
}

if (hw_ver == "B1" && version_is_less(version: fw_ver, test_version: "2.20")) {
  VULN = TRUE;
  fix  = "2.20";
}

if(VULN) {
  report = report_fixed_ver(installed_version: fw_ver, fixed_version:fix, extra: "Hardware revision: " + hw_ver);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
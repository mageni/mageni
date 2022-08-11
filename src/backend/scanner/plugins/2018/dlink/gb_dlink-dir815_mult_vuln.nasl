###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dlink-dir815_mult_vuln.nasl 12444 2018-11-20 14:49:48Z cfischer $
#
# D-Link DIR-815 Rev.B <2.07 Multiple Vulnerabilities
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
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

OS_CPE = "cpe:/o:d-link:dir-815_firmware";
HW_CPE = "cpe:/h:d-link:dir-815";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112256");
  script_version("$Revision: 12444 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-20 15:49:48 +0100 (Tue, 20 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-04-17 09:31:29 +0200 (Tue, 17 Apr 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2015-0150", "CVE-2015-0151", "CVE-2015-0152", "CVE-2015-0153");
  script_name("D-Link DIR-815 Rev.B <2.07 Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dir_detect.nasl");
  script_mandatory_keys("Host/is_dlink_dir_device", "d-link/dir/hw_version");

  script_xref(name:"URL", value:"ftp://ftp2.dlink.com/SECURITY_ADVISEMENTS/DIR-815/REVB/DIR-815_REVB_FIRMWARE_PATCH_NOTES_2.07.B01_EN.PDF");

  script_tag(name:"summary", value:"D-Link Router DIR-815 Rev.B is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"The script checks if the target is an affected device running a vulnerable firmware version.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - The remote administration UI allows remote attackers to bypass intended access restrictions via unspecified vectors. (CVE-2015-0150)

  - Cross-site request forgery (CSRF) allows remote attackers to hijack the authentication of arbitrary users for requests that insert XSS sequences. (CVE-2015-0151)

  - It is possible for remote attackers to obtain sensitive information by leveraging cleartext storage of the administrative password or the wireless key. (CVE-2015-0152, CVE-2015-0153)");

  script_tag(name:"affected", value:"D-Link DIR-815 Rev.B before version 2.07.B01.");

  script_tag(name:"solution", value:"Update to version 2.07.B01.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe: OS_CPE))
  exit(0);

# cpe:/o:d-link:dir-815_firmware:2.06
if (!fw_ver = get_app_version(cpe: OS_CPE, port: port))
  exit(0);

# cpe:/h:d-link:dir-815:b1
if (!hw_ver = get_app_version(cpe: HW_CPE, port: port))
  exit(0);

hw_ver = toupper(hw_ver);

if (hw_ver =~ "^B" && version_is_less(version: fw_ver, test_version: "2.07")) {
  report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2.07.B01", extra: "Hardware revision: " + hw_ver);
  security_message(data: report, port: port);
  exit(0);
}

exit(99);
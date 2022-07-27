###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dlink_dir868l_csrf_vuln.nasl 12444 2018-11-20 14:49:48Z cfischer $
#
# D-Link DIR-868L < 1.20B01 CSRF Vulnerability
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.112281");
  script_version("$Revision: 12444 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-20 15:49:48 +0100 (Tue, 20 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-05-14 12:26:41 +0200 (Mon, 14 May 2018)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2018-10957");
  script_name("D-Link DIR-868L < 1.20B01 CSRF Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dir_detect.nasl");
  script_mandatory_keys("Host/is_dlink_dir_device", "d-link/dir/hw_version");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/147525/D-Link-DIR-868L-1.12-Cross-Site-Request-Forgery.html");
  script_xref(name:"URL", value:"ftp://ftp2.dlink.com/SECURITY_ADVISEMENTS/DIR-868L/REVA/DIR-868L_REVA_FIRMWARE_PATCH_NOTES_1.20B01_EN_WW.pdf");

  script_tag(name:"summary", value:"D-Link DIR-868L devices are prone to a cross-site request forgery (CSRF) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability to perform arbitrary web requests with the identity of the victim
  without being noticed by the victim.");

  script_tag(name:"affected", value:"D-Link DIR-868L before 1.20B01 firmware.");

  script_tag(name:"solution", value:"Upgrade to version 1.20B01 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

CPE = "cpe:/o:d-link:dir-868l_firmware";

include("version_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe:CPE)) exit(0);
if (!version = get_app_version(cpe:CPE, port:port)) exit(0);

if (version_is_less(version: version, test_version: "1.20b01")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.20B01");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
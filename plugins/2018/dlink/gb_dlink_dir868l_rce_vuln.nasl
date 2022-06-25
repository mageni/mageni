###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dlink_dir868l_rce_vuln.nasl 12444 2018-11-20 14:49:48Z cfischer $
#
# D-Link DIR-868L StarHub Firmware Remote Code Execution Vulnerability
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112252");
  script_version("$Revision: 12444 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-20 15:49:48 +0100 (Tue, 20 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-04-09 12:25:00 +0200 (Mon, 09 Apr 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2018-9284");
  script_name("D-Link DIR-868L StarHub Firmware Remote Code Execution Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dir_detect.nasl");
  script_mandatory_keys("Host/is_dlink_dir_device", "d-link/dir/hw_version");

  script_xref(name:"URL", value:"http://www.dlink.com.sg/dir-868l/#firmware");
  script_xref(name:"URL", value:"https://www.fortinet.com/blog/threat-research/fortiguard-labs-discovers-vulnerability-in--d-link-router-dir868.html");

  script_tag(name:"summary", value:"D-Link DIR-868L devices are prone to a pre-authenticated remote code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"This vulnerability is an unauthenticated buffer overflow that occurs when the affected router parses authentication requests.");

  script_tag(name:"impact", value:"Upon successful exploitation, an attacker could then run arbitrary code under the privilege of a web service.");

  script_tag(name:"affected", value:"D-Link DIR-868L with customized Singapore StarHub firmware.");

  script_tag(name:"solution", value:"Upgrade to version 1.21SHCb03 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

CPE = "cpe:/o:d-link:dir-868l_firmware";

include("version_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe:CPE)) exit(0);
if (!version = get_app_version(cpe:CPE, port:port)) exit(0);

if ("shc" >< version && version_is_less(version: version, test_version: "1.21")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.21SHCb03");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mybb_mult_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# MyBB Multiple Vulnerabilities
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/a:mybb:mybb";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107255");
  script_version("$Revision: 12106 $");
  script_cve_id("CVE-2017-16781");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-11-13 09:06:56 +0700 (Mon, 13 Nov 2017)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MyBB Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_mybb_detect.nasl");
  script_mandatory_keys("MyBB/installed");

  script_tag(name:"summary", value:"MyBB is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"MyBB is prone to multiple vulnerabilities:


  - Installer RCE on configuration file write

  - Language file headers RCE.

  - Installer XSS.

  - Mod CP Edit Profile XSS.

  - Insufficient moderator permission check in delayed moderation tools.

  - Announcements HTML filter bypass

  - Language Pack Properties XSS.");

  script_tag(name:"impact", value:"The remote attacker might be able to execute arbitrary code, conduct xss attacks or bypass HTML filters.");

  script_tag(name:"affected", value:"myBB 1.8.12 and prior.");

  script_tag(name:"solution", value:"Update to myBB 1.8.13.");

  script_xref(name:"URL", value:"https://blog.mybb.com/2017/11/07/mybb-1-8-13-released-security-maintenance-release/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "1.8.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.8.13");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

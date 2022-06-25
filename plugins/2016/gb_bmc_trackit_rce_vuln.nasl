###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bmc_trackit_rce_vuln.nasl 12149 2018-10-29 10:48:30Z asteins $
#
# BMC Track-It! Multiple Vulnerabilities
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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

CPE = "cpe:/a:bmc:bmc_track-it!";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106147");
  script_version("$Revision: 12149 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-29 11:48:30 +0100 (Mon, 29 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-07-19 11:00:37 +0700 (Tue, 19 Jul 2016)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2015-8273", "CVE-2015-8274");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("BMC Track-It! Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_bmc_trackit_detect.nasl");
  script_mandatory_keys("bmctrackit/installed");

  script_tag(name:"summary", value:"BMC Track-It! is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"BMC Track-It! is prone to an arbitrary file upload and a execute
any action without authentication via .NET Remoting request.");

  script_tag(name:"impact", value:"An unauthenticated attacker may upload arbitrary files and execute any
action.");

  script_tag(name:"affected", value:"BMC Track-It! versions prior 11.4 Hotfix 3 (11.4.0.440).");

  script_tag(name:"solution", value:"Update to version 11.4 Hotfix 3 (11.4.0.440) or later.");

  script_xref(name:"URL", value:"https://communities.bmc.com/community/bmcdn/bmc_track-it/blog/2016/01/04/track-it-security-advisory-24-dec-2015");
  script_xref(name:"URL", value:"https://blogs.securiteam.com/index.php/archives/2713");


  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "11.4.0.440")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.4.0.440");
  security_message(data: report, port: port);
  exit(0);
}

exit(0);

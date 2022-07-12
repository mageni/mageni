###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_atlassian_fisheye_crucible_rce_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Atlassian FishEye and Crucible RCE Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/a:atlassian:fisheye";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140588");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-12-07 11:26:13 +0700 (Thu, 07 Dec 2017)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2017-14591");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Atlassian FishEye and Crucible RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_atlassian_fisheye_crucible_detect.nasl");
  script_mandatory_keys("atlassian_fisheye_crucible/installed");

  script_tag(name:"summary", value:"Atlassian FishEye and Crucible is prone to a remote command execution
vulnerability.");

  script_tag(name:"insight", value:"Fisheye and Crucible does not check that the name of a file in a Mercurial
repository contained argument parameters. An attacker who has permission to add a repository or commit to a
mercurial repository tracked by Fisheye or Crucible, can execute code of their choice on systems that run a
vulnerable version of Fisheye or Crucible.");

  script_tag(name:"affected", value:"Fisheye and Crucible version 4.5.0 and prior to 4.4.3.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Update to version 4.4.3, 4.5.1 or later.");

  script_xref(name:"URL", value:"https://confluence.atlassian.com/crucible/fisheye-and-crucible-security-advisory-2017-11-29-939939750.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "4.4.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.4.3");
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "4.5.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.5.1");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

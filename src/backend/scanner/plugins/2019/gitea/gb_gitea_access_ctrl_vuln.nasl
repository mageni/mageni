##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_gitea_access_ctrl_vuln.nasl 13750 2019-02-19 07:33:36Z mmartin $
#
# Gitea < 1.6.3 Improper Access Control Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2019 Greenbone Networks GmbH
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

CPE = "cpe:/a:gitea:gitea";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141957");
  script_version("$Revision: 13750 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-19 08:33:36 +0100 (Tue, 19 Feb 2019) $");
  script_tag(name:"creation_date", value:"2019-02-05 09:55:39 +0700 (Tue, 05 Feb 2019)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:P");

  script_cve_id("CVE-2019-1000002");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Gitea < 1.6.3 Improper Access Control Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_gitea_detect.nasl");
  script_mandatory_keys("gitea/detected");

  script_tag(name:"summary", value:"Gitea contains a Incorrect Access Control vulnerability in Delete/Edit file
functionality that can result in the attacker deleting files outside the repository he/she has access to. This
attack appears to be exploitable via the attacker must get write access to 'any' repository including self-created
ones.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Gitea version 1.6.2 and prior.");

  script_tag(name:"solution", value:"Update to version 1.6.3 or later.");

  script_xref(name:"URL", value:"https://github.com/go-gitea/gitea/pull/5631");
  script_xref(name:"URL", value:"https://blog.gitea.io/2019/01/release-of-1.6.3/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "1.6.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.6.3");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

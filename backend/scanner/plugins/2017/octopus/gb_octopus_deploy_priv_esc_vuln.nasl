###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_octopus_deploy_priv_esc_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Octopus Deploy Privilege Escalation Vulnerability
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

CPE = "cpe:/a:octopus:deploy";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140520");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-11-21 14:36:59 +0700 (Tue, 21 Nov 2017)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");

  script_cve_id("CVE-2017-15611");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Octopus Deploy Privilege Escalation Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_octopus_deploy_detect.nasl");
  script_mandatory_keys("octopus_deploy/installed");

  script_tag(name:"summary", value:"In Octopus, an authenticated user who was explicitly granted the permission
to invite new users (aka UserInvite) can invite users to teams with escalated privileges.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Octopus Deploy before version 3.17.7.");

  script_tag(name:"solution", value:"Update to version 3.17.7 or later.");

  script_xref(name:"URL", value:"https://github.com/OctopusDeploy/Issues/issues/3864");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "3.17.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.17.7");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

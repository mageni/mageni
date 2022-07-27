##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpliteadmin_auth_bypass_vuln.nasl 12116 2018-10-26 10:01:35Z mmartin $
#
# phpLiteAdmin Authentication Bypass Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
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

CPE = 'cpe:/a:phpliteadmin_project:phpliteadmin';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141018");
  script_version("$Revision: 12116 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 12:01:35 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-04-24 09:02:06 +0700 (Tue, 24 Apr 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2018-10362");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("phpLiteAdmin Authentication Bypass Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_phpliteadmin_detect.nasl");
  script_mandatory_keys("phpliteadmin/installed");

  script_tag(name:"summary", value:"phpLiteAdmin is prone to a authentication bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The attemptGrant function of the Authorization class uses a wrong comparison.
This can lead to a problem if the password is a number written in scientific notation.");

  script_tag(name:"impact", value:"An attacker may bypass the authentication if the password for a user starts
with a number.");

  script_tag(name:"affected", value:"phpLiteAdmin version 1.9.5 until 1.9.7.1.");

  script_tag(name:"solution", value:"Apply the patch.");

  script_xref(name:"URL", value:"https://github.com/phpLiteAdmin/pla/issues/11");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "1.9.5", test_version2: "1.9.7.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "Apply patch");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

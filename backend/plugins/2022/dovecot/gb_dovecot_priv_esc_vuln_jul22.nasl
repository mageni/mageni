# Copyright (C) 2022 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:dovecot:dovecot";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148464");
  script_version("2022-07-15T06:42:13+0000");
  script_tag(name:"last_modification", value:"2022-07-15 06:42:13 +0000 (Fri, 15 Jul 2022)");
  script_tag(name:"creation_date", value:"2022-07-15 03:57:09 +0000 (Fri, 15 Jul 2022)");
  script_tag(name:"cvss_base", value:"6.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:C/A:N");

  script_cve_id("CVE-2022-30550");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("Dovecot 2.2.x <= 2.3.19.1 Privilege Escalation Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Privilege escalation");
  script_dependencies("gb_dovecot_consolidation.nasl");
  script_mandatory_keys("dovecot/detected");

  script_tag(name:"summary", value:"Dovecot is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"When two passdb configuration entries exist in Dovecot
  configuration, which have the same driver and args settings, the incorrect username_filter and
  mechanism settings can be applied to passdb definitions. These incorrectly applied settings can
  lead to an unintended security configuration and can permit privilege escalation with certain
  configurations involving master user authentication.

  Dovecot documentation does not advise against the use of passdb definitions which have the same
  driver and args settings. One such configuration would be where an administrator wishes to use
  the same pam configuration or passwd file for both normal and master users but use the
  username_filter setting to restrict which of the users is able to be a master user.");

  script_tag(name:"impact", value:"If same passwd file or PAM is used for both normal and master
  users, it is possible for an attacker to become master user.");

  script_tag(name:"affected", value:"Dovecot version 2.2.x through 2.3.19.1.");

  # nb: Only "Fixed in main" with the commit below. Check on https://github.com/dovecot/core/tags
  # if a version later then 2.3.19.1 was released containing the commit below.
  script_tag(name:"solution", value:"No known solution is available as of 15th July, 2022.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://dovecot.org/pipermail/dovecot-news/2022-July/000478.html");
  script_xref(name:"URL", value:"https://github.com/dovecot/core/commit/7bad6a24160e34bce8f10e73dbbf9e5fbbcd1904");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "2.2", test_version2: "2.3.19.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_solarwinds_lem_priv_esc_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# SolarWinds Log and Event Manager SSH Jailbreak and Privilege Escalation Vulnerabilities
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
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

CPE = "cpe:/a:solarwinds:log_and_event_manager";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106698");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-03-28 11:42:33 +0700 (Tue, 28 Mar 2017)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2017-5198", "CVE-2017-5199");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("SolarWinds Log and Event Manager SSH Jailbreak and Privilege Escalation Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_solarwinds_log_event_manager_version.nasl");
  script_mandatory_keys("solarwinds_lem/version");

  script_tag(name:"summary", value:"SolarWinds LEM is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"SolarWinds LEM is prone to multiple vulnerabilities:

  - Incorrect permissions on management scripts allows privilege escalation. (CVE-2017-5198)

  - Authenticated custom shell Jailbreak and command execution (CVE-2017-5199)");

  script_tag(name:"affected", value:"SolarWinds Log and Event Manager version 6.3.1 an prior.");

  script_tag(name:"solution", value:"Upgrade to version 6.3.1 Hotfix 3 or later.");

  script_xref(name:"URL", value:"http://blog.0xlabs.com/2017/03/solarwinds-lem-ssh-jailbreak-and.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE))
  exit(0);

if (version_is_less(version: version, test_version: "6.3.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.3.1 Hotfix 3");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "6.3.1")) {
  hotfix = get_kb_item("solarwinds_lem/hotfix");
  if (!hotfix || int(hotfix) < 3) {
    report = report_fixed_ver(installed_version: version, installed_patch: hotfix, fixed_version: "6.3.1",
                              fixed_patch: "3");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(0);

# Copyright (C) 2021 Greenbone Networks GmbH
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

CPE = "cpe:/a:freeswitch:freeswitch";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146987");
  script_version("2021-10-27T04:34:29+0000");
  script_tag(name:"last_modification", value:"2021-10-27 10:10:16 +0000 (Wed, 27 Oct 2021)");
  script_tag(name:"creation_date", value:"2021-10-27 04:27:43 +0000 (Wed, 27 Oct 2021)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2021-37624", "CVE-2021-41105", "CVE-2021-41145", "CVE-2021-41157",
                "CVE-2021-41158");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("FreeSWITCH < 1.10.7 Multiple Vulnerabilities");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_freeswitch_consolidation.nasl");
  script_mandatory_keys("freeswitch/detected");

  script_tag(name:"summary", value:"FreeSWITCH is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vunerabilities exist:

  - CVE-2021-37624: FreeSWITCH does not authenticate SIP MESSAGE requests, leading to spam and
  message spoofing

  - CVE-2021-41105: FreeSWITCH susceptible to Denial of Service via invalid SRTP packets

  - CVE-2021-41145: FreeSWITCH susceptible to Denial of Service via SIP flooding

  - CVE-2021-41157: FreeSWITCH does not authenticate SIP SUBSCRIBE requests by default

  - CVE-2021-41158: FreeSWITCH vulnerable to SIP digest leak for configured gateways");

  script_tag(name:"affected", value:"FreeSWITCH prior to version 1.10.7.");

  script_tag(name:"solution", value:"Update to version 1.10.7 or later.");

  script_xref(name:"URL", value:"https://github.com/signalwire/freeswitch/security/advisories/GHSA-mjcm-q9h8-9xv3");
  script_xref(name:"URL", value:"https://github.com/signalwire/freeswitch/security/advisories/GHSA-jh42-prph-gp36");
  script_xref(name:"URL", value:"https://github.com/signalwire/freeswitch/security/advisories/GHSA-jvpq-23v4-gp3m");
  script_xref(name:"URL", value:"https://github.com/signalwire/freeswitch/security/advisories/GHSA-g7xg-7c54-rmpj");
  script_xref(name:"URL", value:"https://github.com/signalwire/freeswitch/security/advisories/GHSA-3v3f-99mv-qvj4");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "1.10.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.10.7");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);

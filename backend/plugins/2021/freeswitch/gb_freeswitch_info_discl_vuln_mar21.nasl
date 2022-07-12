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
  script_oid("1.3.6.1.4.1.25623.1.0.146986");
  script_version("2021-10-27T04:34:29+0000");
  script_tag(name:"last_modification", value:"2021-10-27 10:10:16 +0000 (Wed, 27 Oct 2021)");
  script_tag(name:"creation_date", value:"2021-10-27 04:18:09 +0000 (Wed, 27 Oct 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2021-36513");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("FreeSWITCH < 1.10.6 Information Disclosure Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_freeswitch_consolidation.nasl");
  script_mandatory_keys("freeswitch/detected");

  script_tag(name:"summary", value:"FreeSWITCH is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An issue was discovered in function sofia_handle_sip_i_notify
  in sofia.c which may allow attackers to view sensitive information due to an uninitialized value.");

  script_tag(name:"affected", value:"FreeSWITCH prior to version 1.10.6.");

  script_tag(name:"solution", value:"Update to version 1.10.6 or later.");

  script_xref(name:"URL", value:"https://github.com/signalwire/freeswitch/issues/1245");
  script_xref(name:"URL", value:"https://github.com/signalwire/freeswitch/releases/tag/v1.10.6");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "1.10.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.10.6");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);

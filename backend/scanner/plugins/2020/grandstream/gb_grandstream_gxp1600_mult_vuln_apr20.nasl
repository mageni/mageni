# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from the referenced
# advisories, and are Copyright (C) by the respective right holder(s)
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143707");
  script_version("2020-04-15T09:17:37+0000");
  script_tag(name:"last_modification", value:"2020-04-16 10:29:54 +0000 (Thu, 16 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-04-15 08:54:43 +0000 (Wed, 15 Apr 2020)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2020-5738", "CVE-2020-5739");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("Grandstream GXP1600 Series IP Phones <= 1.0.4.152 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_grandstream_gxp_consolidation.nasl");
  script_mandatory_keys("grandstream/gxp/detected");

  script_tag(name:"summary", value:"Grandstream GXP1600 Series IP Phones are prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"Grandstream GXP1600 Series IP Phones are prone to multiple vulnerabilities:

  - Authenticated RCE via Tar Upload (CVE-2020-5738)

  - Authenticated RCE via OpenVPN Configuration File (CVE-2020-5739)");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Grandstream GXP1600 Series IP Phones with firmware version 1.0.4.152 and
  probably prior.");

  script_tag(name:"solution", value:"No known solution is available as of 15th April, 2020.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://medium.com/tenable-techblog/reverse-shell-from-an-openvpn-configuration-file-73fd8b1d38da");
  script_xref(name:"URL", value:"https://www.tenable.com/security/research/tra-2020-22");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:grandstream:gxp1610_firmware",
                     "cpe:/o:grandstream:gxp1615_firmware",
                     "cpe:/o:grandstream:gxp1620_firmware",
                     "cpe:/o:grandstream:gxp1625_firmware",
                     "cpe:/o:grandstream:gxp1628_firmware",
                     "cpe:/o:grandstream:gxp1630_firmware");

if (!version = get_app_version(cpe: cpe_list, nofork: TRUE))
  exit(0);

if (version_is_less_equal(version: version, test_version: "1.0.4.152")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None");
  security_message(port: 0, data: report);
  exit(0);
}

exit(0);

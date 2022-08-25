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

CPE = "cpe:/a:openwrt:openwrt";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148623");
  script_version("2022-08-23T10:11:31+0000");
  script_tag(name:"last_modification", value:"2022-08-23 10:11:31 +0000 (Tue, 23 Aug 2022)");
  script_tag(name:"creation_date", value:"2022-08-23 06:28:21 +0000 (Tue, 23 Aug 2022)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-26 18:22:00 +0000 (Fri, 26 Mar 2021)");

  script_cve_id("CVE-2020-25681", "CVE-2020-25682", "CVE-2020-25683", "CVE-2020-25684",
                "CVE-2020-25685", "CVE-2020-25686", "CVE-2020-25687");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenWRT < 19.07.6 Multiple dnsmasq Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_openwrt_ssh_login_detect.nasl");
  script_mandatory_keys("openwrt/detected");

  script_tag(name:"summary", value:"OpenWRT is prone to multiple vulnerabilities in dnsmasq.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Dnsmasq has two sets of vulnerabilities, one set of memory
  corruption issues handling DNSSEC and a second set of issues validating DNS responses. These
  vulnerabilities could allow an attacker to corrupt memory on the target device and perform cache
  poisoning attacks against the target environment.");

  script_tag(name:"affected", value:"OpenWRT version 19.07.5 and prior.");

  script_tag(name:"solution", value:"Update to version 19.07.6 or later.");

  script_xref(name:"URL", value:"https://openwrt.org/advisory/2021-01-19-1");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "19.07.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "19.07.6");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);

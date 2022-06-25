# Copyright (C) 2021 Greenbone Networks GmbH
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

CPE = "cpe:/a:thekelleys:dnsmasq";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117167");
  script_version("2021-01-19T14:04:53+0000");
  script_tag(name:"last_modification", value:"2021-01-20 11:07:43 +0000 (Wed, 20 Jan 2021)");
  script_tag(name:"creation_date", value:"2021-01-19 13:42:34 +0000 (Tue, 19 Jan 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2020-25681", "CVE-2020-25682", "CVE-2020-25683", "CVE-2020-25684", "CVE-2020-25685",
                "CVE-2020-25686", "CVE-2020-25687");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Dnsmasq < 2.83 Multiple Vulnerabilities (DNSpooq)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("dnsmasq_version.nasl");
  script_mandatory_keys("dnsmasq/installed");

  script_tag(name:"summary", value:"Dnsmasq is prone to multiple vulnerabilities dubbed 'DNSpooq'.");

  script_tag(name:"insight", value:"The following flaws exist:

  - A heap-based buffer overflow in sort_rrset() when DNSSEC is used. (CVE-2020-25681)

  - A buffer overflow in extract_name() function due to missing length check, when
  DNSSEC is enabled. (CVE-2020-25682)

  - A heap-based buffer overflow when DNSSEC is enabled. This flaw is caused by the lack of length
  checks in rfc1035.c:extract_name(), which could be abused to make the code execute memcpy() with
  a negative size in get_rdata(). (CVE-2020-25683)

  - A lack of proper address/port check implemented in the reply_query function. (CVE-2020-25684)

  - A lack of query resource name (RRNAME) checks implemented in the reply_query function.
  (CVE-2020-25685)

  - Multiple DNS query requests for the same resource name (RRNAME) allows for remote attackers to
  spoof DNS traffic, using a birthday attack (RFC 5452). (CVE-2020-25686)

  - A heap-based buffer overflow with large memcpy in sort_rrset() when DNSSEC is enabled. This flaw
  is caused by the lack of length checks in rfc1035.c:extract_name(), which could be abused to make
  the code execute memcpy() with a negative size in sort_rrset(). (CVE-2020-25687)");

  script_tag(name:"impact", value:"- CVE-2020-25681: This can allow a remote attacker to write
  arbitrary data into target device's memory that can lead to memory corruption and other unexpected
  behaviors on the target device.

  - CVE-2020-25682: This can allow a remote attacker to cause memory corruption on the target device.

  - CVE-2020-25683: A remote attacker, who can create valid DNS replies, could use this flaw to cause
  an overflow in a heap-allocated memory. This flaw could be abused to make the code execute memcpy()
  with a negative size in get_rdata() and cause a crash in dnsmasq, resulting in a Denial of Service.

  - CVE-2020-25684: This flaw makes it easier to forge replies to an off-path attacker.

  - CVE-2020-25685: This flaw allows remote attackers to spoof DNS traffic that can lead to DNS cache
  poisoning.

  - CVE-2020-25686: This flaw can lead to DNS cache poisoning.

  - CVE-2020-25687: A remote attacker, who can create valid DNS replies, could use this flaw to cause
  an overflow in a heap-allocated memory. This flaw could be abused be abused to make the code execute
  memcpy() with a negative size in sort_rrset() and cause a crash in dnsmasq, resulting in a Denial of
  Service.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Dnsmasq versions prior to 2.83.");

  script_tag(name:"solution", value:"Update to version 2.83 or later.");

  script_xref(name:"URL", value:"https://www.jsof-tech.com/disclosures/dnspooq/");
  script_xref(name:"URL", value:"https://www.thekelleys.org.uk/dnsmasq/CHANGELOG");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!infos = get_app_version_and_proto(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
proto = infos["proto"];

if(version_is_less(version: version, test_version: "2.83")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.83");
  security_message(port: port, data: report, proto: proto);
  exit(0);
}

exit(99);

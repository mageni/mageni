# Copyright (C) 2009 Greenbone Networks GmbH
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

CPE = "cpe:/a:thekelleys:dnsmasq";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100267");
  script_version("2021-03-26T10:02:15+0000");
  script_tag(name:"last_modification", value:"2021-03-29 10:41:25 +0000 (Mon, 29 Mar 2021)");
  script_tag(name:"creation_date", value:"2009-09-02 11:12:57 +0200 (Wed, 02 Sep 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_bugtraq_id(36121, 36120);
  script_cve_id("CVE-2009-2957", "CVE-2009-2958");
  script_name("Dnsmasq TFTP Service 2.40 - 2.49 Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("gb_dnsmasq_consolidation.nasl");
  script_mandatory_keys("thekelleys/dnsmasq/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36121");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36120");
  script_xref(name:"URL", value:"http://www.coresecurity.com/content/dnsmasq-vulnerabilities");
  script_xref(name:"URL", value:"http://thekelleys.org.uk/dnsmasq/CHANGELOG");

  script_tag(name:"summary", value:"Dnsmasq is prone to a remotely exploitable
  heap-overflow vulnerability because the software fails to properly bounds-check
  user-supplied input before copying it into an insufficiently sized memory buffer.");

  script_tag(name:"insight", value:"NOTE: The TFTP service must be enabled for this issue
  to be exploitable. This is not the default.");

  script_tag(name:"impact", value:"Remote attackers can exploit this issue to execute
  arbitrary machine code in the context of the vulnerable software on the targeted
  user's computer.

  Dnsmasq is also prone to a NULL-pointer dereference vulnerability.
  An attacker can exploit this issue to crash the affected application, denying
  service to legitimate users.");

  script_tag(name:"affected", value:"Dnsmasq 2.40 through 2.49. Older versions are
  probably affected too, but they were not checked.");

  script_tag(name:"solution", value:"Update to version 2.50 or later.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the
  target host.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_full(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
proto = infos["proto"];
location = infos["location"];

if (version_is_less(version: version, test_version: "2.50")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.50", install_path: location);
  security_message(port: port, proto: proto, data: report);
  exit(0);
}

exit(99);
##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pdns_powerdns-advisory-2019-02.nasl 13394 2019-02-01 07:36:10Z mmartin $
#
# PowerDNS Recursor < 4.1.9 DNSSEC Signature Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2019 Greenbone Networks GmbH
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

CPE = 'cpe:/a:powerdns:recursor';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141899");
  script_version("$Revision: 13394 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-01 08:36:10 +0100 (Fri, 01 Feb 2019) $");
  script_tag(name:"creation_date", value:"2019-01-22 09:19:38 +0700 (Tue, 22 Jan 2019)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2019-3807");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PowerDNS Recursor < 4.1.9 DNSSEC Signature Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("pdns_version.nasl");
  script_mandatory_keys("powerdns/recursor/installed");

  script_tag(name:"summary", value:"An issue has been found in PowerDNS Recursor where records in the answer
section of responses received from authoritative servers with the AA flag not set were not properly validated,
allowing an attacker to bypass DNSSEC validation.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"PowerDNS Recursor from 4.1.0 up to and including 4.1.8.");

  script_tag(name:"solution", value:"Upgrade to version 4.1.9 or later.");

  script_xref(name:"URL", value:"https://docs.powerdns.com/recursor/security-advisories/powerdns-advisory-2019-02.html");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_proto(cpe: CPE, port: port))
  exit(0);

version = infos["version"];
proto = infos["proto"];

if (version_in_range(version: version, test_version: "4.1.0", test_version2: "4.1.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.1.9");
  security_message(data: report, port: port, proto: proto);
  exit(0);
}

exit(99);

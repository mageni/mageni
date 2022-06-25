###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_quagga_dos_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Quagga DoS Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/a:quagga:quagga";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140461");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-11-01 12:34:31 +0700 (Wed, 01 Nov 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2017-16227");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Quagga DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_quagga_remote_detect.nasl");
  script_mandatory_keys("quagga/installed");

  script_tag(name:"summary", value:"Quagga is prone to a denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The aspath_put function in bgpd/bgp_aspath.c in Quagga allows remote
attackers to cause a denial of service (session drop) via BGP UPDATE messages, because AS_PATH size calculation
for long paths counts certain bytes twice and consequently constructs an invalid message.");

  script_tag(name:"affected", value:"Quagga prior version 1.2.2.");

  script_tag(name:"solution", value:"Update to version 1.2.2 or later.");

  script_xref(name:"URL", value:"https://lists.quagga.net/pipermail/quagga-dev/2017-September/033284.html");
  script_xref(name:"URL", value:"https://ftp.cc.uoc.gr/mirrors/nongnu.org/quagga/quagga-1.2.2.changelog.txt");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE))
  exit(0);

if (version_is_less(version: version, test_version: "1.2.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.2.2");
  security_message(port: 0, data: report);
  exit(0);
}

exit(0);

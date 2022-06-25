##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_memcached_dos_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Memcached < 1.4.39 DoS Vulnerability
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

CPE = "cpe:/a:memcached:memcached";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106981");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-07-24 15:46:47 +0700 (Mon, 24 Jul 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2017-9951");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Memcached < 1.4.39 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_memcached_detect.nasl");
  script_mandatory_keys("Memcached/detected");

  script_tag(name:"summary", value:"Memcached is prone to a denial of service vulnerability.");

  script_tag(name:"insight", value:"The try_read_command function in memcached.c in memcached allows remote
attackers to cause a denial of service (segmentation fault) via a request to add/set a key, which makes a
comparison between signed and unsigned int and triggers a heap-based buffer over-read.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Memcached version prior to 1.4.39.");

  script_tag(name:"solution", value:"Update to version 1.4.39 or later.");

  script_xref(name:"URL", value:"https://github.com/memcached/memcached/wiki/ReleaseNotes1439");
  script_xref(name:"URL", value:"https://www.twistlock.com/2017/07/13/cve-2017-9951-heap-overflow-memcached-server-1-4-38-twistlock-vulnerability-report/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_proto(cpe: CPE, port: port))
  exit(0);

version  = infos["version"];
proto    = infos["proto"];

if (version_is_less(version: version, test_version: "1.4.39")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.4.39");
  security_message(port: port, proto: proto, data: report);
  exit(0);
}

exit(99);

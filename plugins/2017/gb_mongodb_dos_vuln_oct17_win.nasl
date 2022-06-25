###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mongodb_dos_vuln_oct17_win.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# MongoDB DoS Vulnerability - Oct17 (Windows)
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

CPE = "cpe:/a:mongodb:mongodb";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140492");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-11-07 12:22:09 +0700 (Tue, 07 Nov 2017)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");

  script_cve_id("CVE-2017-15535");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MongoDB DoS Vulnerability - Oct17 (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("gb_mongodb_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mongodb/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"MongoDB is prone to a denial of service vulnerability.");

  script_tag(name:"insight", value:"MongoDB has a disabled-by-default configuration setting,
networkMessageCompressors (aka wire protocol compression), which exposes a vulnerability when enabled that could
be exploited by a malicious attacker to deny service or modify memory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"MongoDB version 3.4.x and 3.5.x.");

  script_tag(name:"solution", value:"Update to version 3.4.10, 3.6.0-rc0 or later.");

  script_xref(name:"URL", value:"https://jira.mongodb.org/browse/SERVER-31273");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "3.4.0", test_version2: "3.4.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.4.10");
  security_message(port: port, data: report);
  exit(0);
}

if (version =~ "^3\.5\.") {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.6.0-rc0");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nghttp2_dos_vuln.nasl 12116 2018-10-26 10:01:35Z mmartin $
#
# nghttp2 < 1.31.1 DoS Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
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

CPE = 'cpe:/a:nghttp2:nghttp2';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140984");
  script_version("$Revision: 12116 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 12:01:35 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-04-16 15:11:28 +0700 (Mon, 16 Apr 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2018-1000168");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("nghttp2 < 1.31.1 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_nghttp2_detect.nasl");
  script_mandatory_keys("nghttp2/detected");

  script_tag(name:"summary", value:"nghttpd2 is prone to a denial of service vulnerability due to a NULL pointer
deference.");

  script_tag(name:"insight", value:"If ALTSVC frame is received by libnghttp2 and it is larger than it can
accept, the pointer field which points to ALTSVC frame payload is left NULL.  Later libnghttp2 attempts to access
another field through the pointer, and gets segmentation fault.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"nghttpd2 version 1.10.0 until 1.31.0.");

  script_tag(name:"solution", value:"Update to version 1.31.1 or later.");

  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2018/q2/38");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "1.10.0", test_version2: "1.31.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.31.1");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);

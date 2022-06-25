###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zoneminder_xss_vuln.nasl 13538 2019-02-08 11:56:06Z cfischer $
#
# ZoneMinder 1.32.3 XSS Vulnerability
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

CPE = "cpe:/a:zoneminder:zoneminder";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141929");
  script_version("$Revision: 13538 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 12:56:06 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2019-01-28 12:57:55 +0700 (Mon, 28 Jan 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2019-6777");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ZoneMinder 1.32.3 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_zoneminder_detect.nasl");
  script_mandatory_keys("zoneminder/installed");

  script_tag(name:"summary", value:"An issue was discovered in ZoneMinder v1.32.3. Reflected XSS exists in
  web/skins/classic/views/plugin.php via the zm/index.php?view=plugin pl parameter.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Apply the provided patch.");

  script_xref(name:"URL", value:"https://github.com/ZoneMinder/zoneminder/issues/2436");
  script_xref(name:"URL", value:"https://github.com/mnoorenberghe/ZoneMinder/commit/59cc65411f02c7e39a270fda3ecb4966d7b48d41");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_equal(version: version, test_version: "1.32.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "Apply patch.");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
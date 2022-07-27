###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nuxeo_platform_dir_trav_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Nuxeo Platform Directory Traversal Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

CPE = "cpe:/a:nuxeo:platform";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106696");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-03-27 14:18:27 +0700 (Mon, 27 Mar 2017)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2017-5869");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nuxeo Platform Directory Traversal Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_nuxeo_platform_detect.nasl");
  script_mandatory_keys("nuxeo_platform/installed");

  script_tag(name:"summary", value:"Nuxeo Platform is prone to a authenticated directory traversal
vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Directory traversal vulnerability in the file import feature allows remote
authenticated users to upload and execute arbitrary JSP code via a .. (dot dot) in the X-File-Name header.");

  script_tag(name:"impact", value:"An authenticated attacker may upload and execute arbitrary JSP code.");

  script_tag(name:"affected", value:"Nuxeo Platform 6.0, 7.1, 7.2 and 7.3.");

  script_tag(name:"solution", value:"Update to version 7.4 or later.");

  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2017/03/23/6");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "6.0", test_version2: "7.3") || version == "lts-2014") {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.4");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);

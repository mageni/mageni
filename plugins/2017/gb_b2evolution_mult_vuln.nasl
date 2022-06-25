###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_b2evolution_mult_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# b2evolution Multiple Vulnerabilities
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

CPE = "cpe:/a:b2evolution:b2evolution";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106537");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-01-24 09:44:44 +0700 (Tue, 24 Jan 2017)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");

  script_cve_id("CVE-2017-5494", "CVE-2017-5480");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("b2evolution Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_b2evolution_detect.nasl");
  script_mandatory_keys("b2evolution/installed");

  script_tag(name:"summary", value:"b2evolution is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"b2evolution is prone to multiple vulnerabilities:

  - Directory traversal vulnerability in inc/files/files.ctrl.php in allows remote authenticated users to read or
delete arbitrary files by leveraging back-office access to provide a .. (dot dot) in the fm_selected array
parameter. (CVE-2017-5480)

  - Multiple cross-site scripting (XSS) vulnerabilities in the file types table allow remote authenticated users to
inject arbitrary web script or HTML via a .swf file in a comment frame or avatar frame. (CVE-2017-5494)");

  script_tag(name:"affected", value:"b2evolution 6.8.3 and prior.");

  script_tag(name:"solution", value:"Upgrade to version 6.8.4 or later");

  script_xref(name:"URL", value:"https://github.com/b2evolution/b2evolution/issues/35");
  script_xref(name:"URL", value:"https://github.com/b2evolution/b2evolution/issues/34");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "6.8.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.8.4");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);

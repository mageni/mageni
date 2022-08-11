###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nagvis_xss_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# NagVis XSS Vulnerability
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

CPE = "cpe:/a:nagvis:nagvis";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106638");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-03-08 12:16:59 +0700 (Wed, 08 Mar 2017)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2017-6393");
  script_bugtraq_id(96537);

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("NagVis XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_nagvis_detect.nasl");
  script_mandatory_keys("nagvis/installed");

  script_tag(name:"summary", value:"NagVis is prone to a cross-site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability exists due to insufficient filtration of user-supplied
data passed to the 'nagvis-master/share/userfiles/gadgets/std_table.php' URL.");

  script_tag(name:"impact", value:"An attacker could execute arbitrary HTML and script code in browser in
context of the vulnerable website.");

  script_tag(name:"affected", value:"Nagvis 1.8.x, 1.9b12 and prior.");

  script_tag(name:"solution", value:"Apply the provided patch or update to 1.9b13 or later.");

  script_xref(name:"URL", value:"https://github.com/NagVis/nagvis/issues/91");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "1.8", test_version2: "1.8.5") ||
    version_in_range(version: version, test_version: "1.9b1", test_version2: "1.9b12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.9b13");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);

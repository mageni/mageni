###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vtscada_mult_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# VTScada Multiple Vulnerabilities
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

CPE = 'cpe:/a:trihedral:vtscada';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106906");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-06-23 16:17:12 +0700 (Fri, 23 Jun 2017)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2017-6043", "CVE-2017-6045", "CVE-2017-6053");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("VTScada Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_vtscada_detect.nasl");
  script_mandatory_keys("vtscada/detected");

  script_tag(name:"summary", value:"VTScada is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"VTScada is prone to multiple vulnerabilities:

  - The client does not properly validate the input or limit the amount of resources that are utilized by an
attacker, which can be used to consume more resources than are available. (CVE-2017-6043)

  - Some files are exposed within the web server application to unauthenticated users. These files may contain
sensitive configuration information. (CVE-2017-6045)

  - A cross-site scripting vulnerability may allow JavaScript code supplied by the attacker to execute within the
user's browser. (CVE-2017-6053)");

  script_tag(name:"affected", value:"VTScada Versions prior to 11.2.26");

  script_tag(name:"solution", value:"Update to version 11.2.26 or later.");

  script_xref(name:"URL", value:"https://ics-cert.us-cert.gov/advisories/ICSA-17-164-01");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "11.2.26")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.2.26");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

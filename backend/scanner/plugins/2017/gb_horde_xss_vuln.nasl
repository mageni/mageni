##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_horde_xss_vuln.nasl 12554 2018-11-28 08:17:27Z asteins $
#
# Horde Groupware Multiple Vulnerabilities
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

CPE = "cpe:/a:horde:horde_groupware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140527");
  script_version("$Revision: 12554 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-28 09:17:27 +0100 (Wed, 28 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-11-22 17:09:33 +0700 (Wed, 22 Nov 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2017-16906", "CVE-2017-16907", "CVE-2017-16906", "CVE-2017-17781");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Horde Groupware Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("horde_detect.nasl");
  script_mandatory_keys("horde/installed");

  script_tag(name:"summary", value:"Horde Groupware is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"Horde Groupware is prone to multiple vulnerabilities:

  - Multiple cross-site scripting vulnerabilities in the URL field in a 'Calendar -> New Event' action, the Color
field in a Create Task List action and the Name field during creation of a new Resource. (CVE-2017-16906,
CVE-2017-16907, CVE-2017-16906)

  - SQL Injection exists via the group parameter to /services/prefs.php or the homePostalCode parameter to
/turba/search.php.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"https://code610.blogspot.com/2017/11/rce-via-xss-horde-5219.html");
  script_xref(name:"URL", value:"https://code610.blogspot.com/2017/12/modus-operandi-horde-52x.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "5.2.22")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);

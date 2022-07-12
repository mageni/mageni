###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_juniper_screenos_jsa10782.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Juniper ScreenOS Multiple XSS Vulnerabilities
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

CPE = 'cpe:/o:juniper:screenos';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106947");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-07-13 14:37:40 +0700 (Thu, 13 Jul 2017)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");

  script_cve_id("CVE-2017-2335", "CVE-2017-2336", "CVE-2017-2337", "CVE-2017-2338", "CVE-2017-2339");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Juniper ScreenOS Multiple XSS Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_family("General");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_screenos_version.nasl");
  script_mandatory_keys("ScreenOS/version");

  script_tag(name:"summary", value:"ScreenOS is prone to multiple XSS vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A security researcher testing a Juniper NetScreen Firewall+VPN found
multiple stored cross-site scripting vulnerabilities that could be used to elevate privileges through the
NetScreen WebUI.  A user with the 'security' role can inject HTML/JavaScript content into the management session
of other users including the administrator.  This enables the lower-privileged user to effectively execute
commands with the permissions of an administrator.");

  script_tag(name:"solution", value:"Update to ScreenOS 6.3.0r24 or later.");

  script_xref(name:"URL", value:"http://kb.juniper.net/JSA10782");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE))
  exit(0);

display_version = version;

version = str_replace(string: version, find: "r", replace: ".");
version = str_replace(string: version, find: "-", replace: ".");

display_fix = '6.3.0r24';

if (version_is_less(version: version, test_version: '6.3.0.24')) {
  report = report_fixed_ver(installed_version: display_version, fixed_version: display_fix);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bugzilla_41141.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# Bugzilla 'time-tracking' Information Disclosure Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

CPE = "cpe:/a:mozilla:bugzilla";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100699");
  script_version("$Revision: 13960 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-07-06 13:44:35 +0200 (Tue, 06 Jul 2010)");
  script_bugtraq_id(41141);
  script_cve_id("CVE-2010-1204");

  script_name("Bugzilla 'time-tracking' Information Disclosure Vulnerability");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/41141");
  script_xref(name:"URL", value:"http://www.bugzilla.org");
  script_xref(name:"URL", value:"http://www.bugzilla.org/security/3.2.6/");

  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("bugzilla_detect.nasl");
  script_mandatory_keys("bugzilla/installed");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"summary", value:"Bugzilla is prone to an information-disclosure vulnerability.

Exploits may allow attackers to obtain potentially sensitive information that may aid in other attacks.

This issue affects the following:

Bugzilla 2.17.1 through 3.2.6, Bugzilla 3.3.1 through 3.4.6, Bugzilla 3.5.1 through 3.6, Bugzilla 3.7");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!vers = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: vers, test_version: "2.17.1", test_version2:"3.2.6") ||
    version_in_range(version: vers, test_version: "3.3.1", test_version2:"3.4.6")  ||
    version_in_range(version: vers, test_version: "3.5.1", test_version2:"3.6")    ||
    version_is_equal(version: vers, test_version:"3.7")) {
  security_message(port:port);
  exit(0);
}

exit(0);

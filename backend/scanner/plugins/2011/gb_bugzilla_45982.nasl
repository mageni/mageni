###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bugzilla_45982.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Bugzilla Multiple Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103045");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-01-26 13:20:54 +0100 (Wed, 26 Jan 2011)");
  script_bugtraq_id(45982);
  script_cve_id("CVE-2010-4567", "CVE-2010-4568", "CVE-2010-4569", "CVE-2010-4570", "CVE-2011-0046", "CVE-2011-0048");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Bugzilla Multiple Vulnerabilities");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/45982");
  script_xref(name:"URL", value:"http://www.bugzilla.org/security/3.2.9/");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("bugzilla_detect.nasl");
  script_mandatory_keys("bugzilla/installed");

  script_tag(name:"solution", value:"Vendor updates are available. Please see the references for more
information.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Bugzilla is prone to the following vulnerabilities:

1. A security-bypass issue.

2. Multiple cross-site scripting vulnerabilities.

3. Multiple cross-site request-forgery vulnerabilities.

Successfully exploiting these issues may allow an attacker to bypass certain security restrictions, execute
arbitrary script code in the browser of an unsuspecting user, steal cookie-based authentication credentials or
perform certain administrative actions and perform actions in the vulnerable application in the context of the
victim.

The following versions are vulnerable:

3.1.x versions prior to 3.2.10

3.2.x versions prior to 3.4.10

3.3.x versions prior to 3.6.4

4.x versions prior to 4.0rc2");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!vers = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version:vers, test_version: "3.6", test_version2:"3.6.3") ||
    version_in_range(version:vers, test_version: "3.4", test_version2:"3.4.9") ||
    version_in_range(version:vers, test_version: "3.2", test_version2:"3.2.9") ||
    version_in_range(version:vers, test_version: "4.0", test_version2:"4.0rc1")) {
  security_message(port: port);
  exit(0);
}

exit(0);

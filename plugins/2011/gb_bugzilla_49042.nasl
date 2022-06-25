###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bugzilla_49042.nasl 12018 2018-10-22 13:31:29Z mmartin $
#
# Bugzilla Multiple Security Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.103215");
  script_version("$Revision: 12018 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-22 15:31:29 +0200 (Mon, 22 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-08-22 16:04:33 +0200 (Mon, 22 Aug 2011)");
  script_bugtraq_id(49042);
  script_cve_id("CVE-2011-2379", "CVE-2011-2380", "CVE-2011-2381", "CVE-2011-2976", "CVE-2011-2977", "CVE-2011-2978",
               "CVE-2011-2979");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Bugzilla Multiple Security Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49042");
  script_xref(name:"URL", value:"http://www.bugzilla.org");
  script_xref(name:"URL", value:"http://www.bugzilla.org/security/3.4.11/");

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

1. A security-bypass vulnerability.

2. An email header-injection vulnerability.

3. Multiple information-disclosure vulnerabilities.

4. Multiple cross-site scripting vulnerabilities.

Successfully exploiting these issues may allow an attacker to bypass certain security restrictions, obtain
sensitive information, execute arbitrary script code in the browser of an unsuspecting user, steal cookie-based
authentication credentials, and perform actions in the vulnerable application in the context of the victim.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!vers = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: vers, test_version:"4.1", test_version2:"4.1.2") ||
    version_in_range(version: vers, test_version:"4.0", test_version2:"4.0.1") ||
    version_in_range(version: vers, test_version:"3.6", test_version2:"3.6.5") ||
    version_in_range(version: vers, test_version:"3.4", test_version2:"3.4.11")) {
  security_message(port:port);
  exit(0);
}

exit(0);

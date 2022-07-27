###############################################################################
# OpenVAS Vulnerability Test
# $Id: horde_29745.nasl 14031 2019-03-07 10:47:29Z cfischer $
#
# Horde Turba 'services/obrowser/index.php' HTML Injection
# Vulnerability
#
# Authors
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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

CPE = 'cpe:/a:horde:horde_groupware';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100116");
  script_version("$Revision: 14031 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-04-10 19:06:18 +0200 (Fri, 10 Apr 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2008-3330");
  script_bugtraq_id(29745);

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Horde Turba 'services/obrowser/index.php' HTML Injection Vulnerability");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("horde_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("horde/installed");

  script_tag(name:"summary", value:"Horde Turba is prone to an HTML-injection vulnerability because it fails to
  properly sanitize user-supplied input.");

  script_tag(name:"impact", value:"Attacker-supplied HTML and script code would execute in the context of the
  affected site, potentially allowing the attacker to steal cookie-based authentication credentials or to control
  how the site is rendered to the user, other attacks are also possible.");

  script_tag(name:"affected", value:"Horde 3.1.7, 3.2, and prior versions are vulnerable.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/29745");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version:version, test_version:"3.1", test_version2:"3.1.7") ||
    version_in_range(version:version, test_version:"3.2", test_version2:"3.2.0")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"See references");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
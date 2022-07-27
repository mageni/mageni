###############################################################################
# OpenVAS Vulnerability Test
# $Id: horde_33491.nasl 14031 2019-03-07 10:47:29Z cfischer $
#
# Horde Products Local File Include and Cross Site Scripting
# Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.100118");
  script_version("$Revision: 14031 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-04-10 19:06:18 +0200 (Fri, 10 Apr 2009)");
  script_bugtraq_id(33491);
  script_cve_id("CVE-2009-0932");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Horde Products Local File Include and Cross Site Scripting Vulnerabilities");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("horde_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("horde/installed");

  script_tag(name:"summary", value:"Horde products are prone to a local file-include vulnerability and a
  cross-site scripting vulnerability because they fail to properly sanitize user-supplied input.");

  script_tag(name:"impact", value:"An attacker can exploit the local file-include vulnerability using
  directory-traversal strings to view and execute local files within the context of the webserver process.
  Information harvested may aid in further attacks.

  The attacker may leverage the cross-site scripting issue to execute arbitrary script code in the browser of an
  unsuspecting user in the context of the affected site. This may let the attacker steal cookie-based authentication
  credentials and launch other attacks.");

  script_tag(name:"affected", value:"Horde 3.2.4 and 3.3.3

  Horde Groupware 1.1.5");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33491");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version:version, test_version:"3.3", test_version2:"3.3.2") ||
    version_in_range(version:version, test_version:"3.2", test_version2:"3.2.3") ) {
  report = report_fixed_ver(installed_version:version, fixed_version:"See references");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
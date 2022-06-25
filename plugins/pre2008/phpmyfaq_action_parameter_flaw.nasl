# OpenVAS Vulnerability Test
# $Id: phpmyfaq_action_parameter_flaw.nasl 13975 2019-03-04 09:32:08Z cfischer $
# Description: phpMyFAQ action parameter arbitrary file disclosure vulnerability
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
#
# Copyright:
# Copyright (C) 2004 David Maciejak
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

CPE = 'cpe:/a:phpmyfaq:phpmyfaq';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14258");
  script_version("$Revision: 13975 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-04 10:32:08 +0100 (Mon, 04 Mar 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2004-2255");
  script_bugtraq_id(10374);

  script_name("phpMyFAQ action parameter arbitrary file disclosure vulnerability");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");

  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("phpmyfaq_detect.nasl");
  script_mandatory_keys("phpmyfaq/installed");
  script_require_ports("Services/www", 80);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Upgrade to phpMyFAQ 1.3.13 or newer.");

  script_tag(name:"summary", value:"The remote web server contains a PHP script that permits information
disclosure of local files.

The version of phpMyFAQ on the remote host contains a flaw that may lead to an unauthorized information
disclosure.  The problem is that user input passed to the 'action' parameter is not properly verified before
being used to include files, which could allow an remote attacker to view any accessible file on the system,
resulting in a loss of confidentiality.");

  script_xref(name:"URL", value:"http://security.e-matters.de/advisories/052004.html");
  script_xref(name:"URL", value:"http://www.phpmyfaq.de/advisory_2004-05-18.php");

  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "1.3.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.3.13");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

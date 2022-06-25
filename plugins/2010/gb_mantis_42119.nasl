###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mantis_42119.nasl 12958 2019-01-07 10:57:12Z cfischer $
#
# Mantis Attachment HTML Injection Vulnerability
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

CPE = "cpe:/a:mantisbt:mantisbt";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100738");
  script_version("$Revision: 12958 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-07 11:57:12 +0100 (Mon, 07 Jan 2019) $");
  script_tag(name:"creation_date", value:"2010-08-03 13:36:27 +0200 (Tue, 03 Aug 2010)");
  script_bugtraq_id(42119);

  script_name("Mantis Attachment HTML Injection Vulnerability");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/42119");
  script_xref(name:"URL", value:"http://www.mantisbt.org/bugs/changelog_page.php");
  script_xref(name:"URL", value:"http://www.mantisbt.org/");
  script_xref(name:"URL", value:"http://www.mantisbt.org/blog/?p=113");

  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("mantis_detect.nasl");
  script_mandatory_keys("mantisbt/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Updates are available, please see the references for more information.");

  script_tag(name:"summary", value:"Mantis is prone to an HTML-injection vulnerability because it fails to
  properly sanitize user-supplied input before using it in dynamically generated content.");

  script_tag(name:"impact", value:"Successful exploits will allow attacker-supplied HTML and script
  code to run in the context of the affected browser, potentially allowing the attacker to steal cookie-based
  authentication credentials or to control how the site is rendered to the user. Other attacks are also possible.");

  script_tag(name:"affected", value:"Mantis 1.2.1 is vulnerable, other versions may also be affected.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos['version'];
path = infos['location'];

if (version_is_less(version: version, test_version: "1.2.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.2.2", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
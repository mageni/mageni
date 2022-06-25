###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_46787.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Joomla! Prior to 1.6.1 Multiple Security Vulnerabilities
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

CPE = "cpe:/a:joomla:joomla";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103114");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-03-09 13:38:24 +0100 (Wed, 09 Mar 2011)");
  script_bugtraq_id(46787);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Joomla! Prior to 1.6.1 Multiple Security Vulnerabilities");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/46787");
  script_xref(name:"URL", value:"http://www.joomla.org/announcements/release-news/5350-joomla-161-released.html");
  script_xref(name:"URL", value:"http://www.joomla.org/");

  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("joomla/installed");

  script_tag(name:"solution", value:"The vendor released a patch. Please see the references for more
information.");

  script_tag(name:"summary", value:"Joomla! is prone to multiple security vulnerabilities including:

  - An SQL-injection issue

  - A path-disclosure vulnerability

  - Multiple cross-site scripting issues

  - Multiple information-disclosure vulnerabilities

  - A URI-redirection vulnerability

  - A security-bypass vulnerability

  - A cross-site request-forgery vulnerability

  - A denial-of-service vulnerability");

  script_tag(name:"impact", value:"An attacker can exploit these vulnerabilities to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected site, steal cookie-based authentication
credentials, disclose or modify sensitive information, exploit latent vulnerabilities in the underlying database,
deny service to legitimate users, redirect a victim to a potentially malicious site, or perform unauthorized
actions. Other attacks are also possible.");

  script_tag(name:"affected", value:"Versions prior to Joomla! 1.6.1 are vulnerable.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe:CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "1.6.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.6.1");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

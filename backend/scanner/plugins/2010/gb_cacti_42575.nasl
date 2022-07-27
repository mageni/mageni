###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cacti_42575.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# Cacti Cross Site Scripting and HTML Injection Vulnerabilities
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

CPE = "cpe:/a:cacti:cacti";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100764");
  script_version("$Revision: 13960 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-08-30 14:30:07 +0200 (Mon, 30 Aug 2010)");
  script_bugtraq_id(42575);
  script_cve_id("CVE-2010-2543", "CVE-2010-2544", "CVE-2010-2545");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cacti Cross Site Scripting and HTML Injection Vulnerabilities");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/42575");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=459105");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=459229");
  script_xref(name:"URL", value:"http://cacti.net/");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("cacti_detect.nasl");
  script_mandatory_keys("cacti/installed");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"summary", value:"Cacti is prone to cross-site-scripting and HTML-injection vulnerabilities
because it fails to properly sanitize user-supplied input before using it in dynamically generated content.

Attacker-supplied HTML and script code would run in the context of the affected browser, potentially allowing the
attacker to steal cookie-based authentication credentials or to control how the site is rendered to the user.
Other attacks are also possible.

Versions prior to Cacti 0.8.7g are vulnerable.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!vers = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: vers, test_version: "0.8.7g")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "0.8.7g");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cacti_50671.nasl 12018 2018-10-22 13:31:29Z mmartin $
#
# Cacti Unspecified SQL Injection and Cross Site Scripting Vulnerabilities
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

CPE = "cpe:/a:cacti:cacti";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103319");
  script_bugtraq_id(50671);
  script_cve_id("CVE-2011-4824", "CVE-2014-2326");
  script_version("$Revision: 12018 $");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cacti Unspecified SQL Injection and Cross Site Scripting Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50671");
  script_xref(name:"URL", value:"http://cacti.net/");
  script_xref(name:"URL", value:"http://www.cacti.net/release_notes_0_8_7h.php");

  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-22 15:31:29 +0200 (Mon, 22 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-11-15 08:09:39 +0100 (Tue, 15 Nov 2011)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("cacti_detect.nasl");
  script_mandatory_keys("cacti/installed");

  script_tag(name:"solution", value:"The vendor has released fixes. Please see the references for details.");

  script_tag(name:"summary", value:"Cacti is prone to an SQL-injection vulnerability and a cross-site scripting
vulnerability because it fails to sufficiently sanitize user-supplied data.

Exploiting these issues could allow an attacker to steal cookie-based authentication credentials, compromise the
application, access or modify data, or exploit latent vulnerabilities in the underlying database.

Cacti 0.8.7g is vulnerable. Other versions may also be affected.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!vers = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: vers, test_version: "0.8.7h")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "0.8.7h");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);

###############################################################################
# OpenVAS Vulnerability Test
# $Id: dokeos_34928.nasl 14031 2019-03-07 10:47:29Z cfischer $
#
# Dokeos Multiple Remote Input Validation Vulnerabilities
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

CPE = 'cpe:/a:dokeos:dokeos';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100200");
  script_version("$Revision: 14031 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-05-14 12:53:07 +0200 (Thu, 14 May 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-2004");
  script_bugtraq_id(34928);

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Dokeos Multiple Remote Input Validation Vulnerabilities");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("dokeos_detect.nasl");
  script_mandatory_keys("dokeos/installed");

  script_tag(name:"summary", value:"Dokeos is prone to multiple input-validation vulnerabilities, including
  SQL-injection, HTML-injection, cross-site scripting, and cross-site request-forgery issues.");

  script_tag(name:"impact", value:"Attackers can exploit these issues to execute arbitrary script code in the
  context of the webserver, compromise the application, obtain sensitive information, steal cookie-based authentication
  credentials from legitimate users of the site, modify the way the site is rendered, perform certain unauthorized
  actions in the context of a user, access or modify data, or exploit latent vulnerabilities in the underlying database.");

  script_tag(name:"affected", value:"Dokeos 1.8.5 is affected, prior versions may also be affected.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34928");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "1.8.5")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"unknown");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
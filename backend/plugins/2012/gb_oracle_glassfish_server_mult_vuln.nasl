###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_glassfish_server_mult_vuln.nasl 11878 2018-10-12 12:40:08Z cfischer $
#
# Oracle GlassFish Server Multiple XSS and CSRF Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = 'cpe:/a:oracle:glassfish_server';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802624");
  script_version("$Revision: 11878 $");
  script_bugtraq_id(53118, 53136);
  script_cve_id("CVE-2012-0550", "CVE-2012-0551");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 14:40:08 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-05-07 16:16:16 +0530 (Mon, 07 May 2012)");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Oracle GlassFish Server Multiple XSS and CSRF Vulnerabilities");

  script_xref(name:"URL", value:"http://secunia.com/advisories/48798");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1026941");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18764");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpuapr2012-366314.html");
  script_xref(name:"URL", value:"http://www.security-assessment.com/files/documents/advisory/Oracle_GlassFish_Server_REST_CSRF.pdf");
  script_xref(name:"URL", value:"http://www.security-assessment.com/files/documents/advisory/Oracle_GlassFish_Server_Multiple_XSS.pdf");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("GlassFish_detect.nasl");
  script_mandatory_keys("GlassFish/installed");
  script_require_ports("Services/www", 8080);

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert arbitrary HTML
and script code, which will be executed in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"Oracle GlassFish Server version 3.1.1");

  script_tag(name:"insight", value:"Multiple flaws are due to

  - Input passed via multiple parameters to various scripts is not properly sanitised before being returned to the
user. This can be exploited to execute arbitrary HTML and script code in a user's browser session in context of an
affected site.

  - The application allows users to perform certain actions via HTTP requests without performing proper validity
checks to verify the requests.");

  script_tag(name:"summary", value:"This host is running Oracle GlassFish Server and is prone to multiple
vulnerabilities.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_equal(version: version, test_version: "3.1.1")) {
  security_message(port:port);
  exit(0);
}

exit(99);

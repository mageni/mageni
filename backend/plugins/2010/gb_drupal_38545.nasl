###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_drupal_38545.nasl 14033 2019-03-07 11:09:35Z cfischer $
#
# Drupal Prior to 6.16 and 5.22 Multiple Security Vulnerabilities
#
# Authors:
# Michael Meyer
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

CPE = "cpe:/a:drupal:drupal";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100523");
  script_version("$Revision: 14033 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 12:09:35 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-03-09 22:32:06 +0100 (Tue, 09 Mar 2010)");
  script_bugtraq_id(38545);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Drupal Prior to 6.16 and 5.22 Multiple Security Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38545");
  script_xref(name:"URL", value:"http://drupal.org");
  script_xref(name:"URL", value:"http://drupal.org/node/731710");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("drupal_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("drupal/installed");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Updates are available. Please see the references for details.");

  script_tag(name:"summary", value:"Drupal is prone to multiple vulnerabilities, including cross-site
  scripting issues, a phishing issue, and a security-bypass issue.");

  script_tag(name:"impact", value:"An attacker may leverage these issues to execute arbitrary code in the
  browser of an unsuspecting user in the context of the affected site, steal cookie-based authentication
  credentials, bypass security restrictions, or perform other attacks.");

  script_tag(name:"affected", value:"Drupal 5.x prior to 5.22 Drupal 6.x prior to 6.16.");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version( cpe:CPE, port:port, version_regex:"^[0-9]\.[0-9]+" ) )
  exit(0);

if(version_in_range(version:vers, test_version:"5", test_version2:"5.21") ||
   version_in_range(version:vers, test_version:"6", test_version2:"6.15")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"5.22/6.16");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
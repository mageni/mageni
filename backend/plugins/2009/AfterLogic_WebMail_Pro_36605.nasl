###############################################################################
# OpenVAS Vulnerability Test
# $Id: AfterLogic_WebMail_Pro_36605.nasl 14031 2019-03-07 10:47:29Z cfischer $
#
# AfterLogic WebMail Pro Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
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

CPE = "cpe:/a:afterlogic:mailbee_webmail_pro";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100314");
  script_version("$Revision: 14031 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-10-20 18:54:22 +0200 (Tue, 20 Oct 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-4743");
  script_bugtraq_id(36605);

  script_name("AfterLogic WebMail Pro Multiple Cross Site Scripting Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("AfterLogic_WebMail_Pro_detect.nasl");
  script_mandatory_keys("AfterLogicWebMailPro/installed");
  script_require_ports("Services/www", 80);

  script_tag(name:"solution", value:"Reports indicate that the vendor addressed these issues in WebMail Pro
  4.7.11, but Symantec has not confirmed this. Please contact the vendor for more information.");

  script_tag(name:"summary", value:"AfterLogic WebMail Pro is prone to multiple cross-site scripting
  vulnerabilities because the application fails to sufficiently sanitize user-supplied data.");

  script_tag(name:"impact", value:"Attacker-supplied HTML or JavaScript code could run in the context of
  the affected site, potentially allowing the attacker to steal cookie-based authentication credentials.
  Other attacks are also possible.");

  script_tag(name:"affected", value:"AfterLogic WebMail Pro 4.7.10 and prior versions are affected.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36605");
  script_xref(name:"URL", value:"http://www.afterlogic.com/");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "4.7.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
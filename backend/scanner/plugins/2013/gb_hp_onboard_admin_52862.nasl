###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_onboard_admin_52862.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# HP Onboard Administrator Multiple Security Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

CPE = "cpe:/a:hp:onboard_administrator";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103795");
  script_bugtraq_id(52862);
  script_cve_id("CVE-2012-0128", "CVE-2012-0129", "CVE-2012-0130");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 11865 $");
  script_name("HP Onboard Administrator Multiple Security Vulnerabilities");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52862");
  script_xref(name:"URL", value:"http://h18004.www1.hp.com/products/blades/components/onboard/index.html?jumpid=reg_R1002_USEN");
  script_xref(name:"URL", value:"http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c03263573");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-10-01 11:28:03 +0200 (Tue, 01 Oct 2013)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_hp_onboard_administrator_detect.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"An attacker may exploit these issues to obtain sensitive information,
bypass certain security restrictions, and redirect a user to a
potentially malicious site. This may aid in phishing attacks.");
  script_tag(name:"vuldetect", value:"Check if HP Onboard Administrator version is < 3.50");
  script_tag(name:"insight", value:"HP Onboard Administrator is prone to:

1. A URI-redirection vulnerability

2. An information-disclosure vulnerability

3. A security-bypass vulnerability");
  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");
  script_tag(name:"summary", value:"HP Onboard Administrator is prone to multiple security vulnerabilities.");
  script_tag(name:"affected", value:"HP Onboard Administrator (OA) before 3.50");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))exit(0);
if(vers = get_app_version(cpe:CPE, port:port)) {
  if(version_is_less(version: vers, test_version: "3.50")) {
    security_message(port:port);
    exit(0);
  }
}

exit(0);

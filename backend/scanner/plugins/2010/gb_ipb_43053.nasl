###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ipb_43053.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# Invision Power Board BBCode Cross Site Scripting Vulnerability
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

CPE = "cpe:/a:invision_power_services:invision_power_board";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100794");
  script_version("$Revision: 13960 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-09-09 16:30:22 +0200 (Thu, 09 Sep 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2010-3424");
  script_bugtraq_id(43053);

  script_name("Invision Power Board BBCode Cross Site Scripting Vulnerability");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/43053");
  script_xref(name:"URL", value:"http://www.invisionpower.com");
  script_xref(name:"URL", value:"http://www.invisionpower.com/products/board/");
  script_xref(name:"URL", value:"http://community.invisionpower.com/topic/320838-ipboard-31x-security-patch-released/");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("invision_power_board_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("invision_power_board/installed");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Updates are available. Please see the references for details.");

  script_tag(name:"summary", value:"Invision Power Board is prone to a cross-site scripting vulnerability
  because it fails to sufficiently sanitize user-supplied data.");

  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary HTML and
  script code in the browser of an unsuspecting user in the context of the affected site. This may
  allow the attacker to steal cookie-based authentication credentials and to launch other attacks.");

  script_tag(name:"affected", value:"Invision Power Board 3.1.2 is vulnerable. Other versions may also
  be affected.");

  exit(0);
}

include("http_func.inc");

include("host_details.inc");
include("version_func.inc");

port = get_app_port(cpe:CPE);
if(vers = get_app_version(cpe:CPE, port:port)) {
  if(version_is_less_equal(version: vers, test_version: "3.1.2")) {
    security_message(port:port);
    exit(0);
  }
}

exit(0);
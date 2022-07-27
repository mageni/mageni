# OpenVAS Vulnerability Test
# $Id: bea_password.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: BEA WebLogic Operator/Admin Password Disclosure Vulnerability
#
# Authors:
# Astharot <astharot@zone-h.org>
#
# Copyright:
# Copyright (C) 2004 Astharot
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12043");
  script_version("2019-04-11T14:06:24+0000");
  script_tag(name:"last_modification", value:"2019-04-11 14:06:24 +0000 (Thu, 11 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-1757");
  script_bugtraq_id(9501);
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_name("BEA WebLogic Operator/Admin Password Disclosure Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 Astharot");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("WebLogic/banner");

  script_xref(name:"URL", value:"http://dev2dev.bea.com/resourcelibrary/advisoriesnotifications/BEA04_51.00.jsp");

  script_tag(name:"solution", value:"The vendor has release updates. Please see the references for more information.");

  script_tag(name:"summary", value:"The remote web server is running WebLogic.

  BEA WebLogic Server and WebLogic Express are reported prone to a vulnerability
  that may result in the disclosure of Operator or Admin passwords.");

  script_tag(name:"impact", value:"An attacker who has interactive access to the affected
  managed server, may potentially exploit this issue in a timed attack to harvest credentials
  when the managed server fails during the boot process.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);
banner = get_http_banner(port:port);
if(!banner || "WebLogic" >!< banner)
  exit(0);

if ("Temporary Patch for CR127930" >< banner)
  exit(0);

if(egrep(pattern:"^Server:.*WebLogic ([6-8]\..*)", string:banner)) {
  security_message(port:port);
  exit(0);
}

exit(99);
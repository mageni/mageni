###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mutiny_56165.nasl 11855 2018-10-12 07:34:51Z cfischer $
#
# Mutiny  Command Injection Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
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

CPE = "cpe:/a:mutiny:standard";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103589");
  script_bugtraq_id(56165);
  script_cve_id("CVE-2012-3001");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_version("$Revision: 11855 $");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Mutiny Command Injection Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56165");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 09:34:51 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-10-23 10:29:30 +0200 (Tue, 23 Oct 2012)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("gb_mutiny_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Mutiny/installed");

  script_tag(name:"solution", value:"Updates are available. Please see the references for details.");

  script_tag(name:"summary", value:"Mutiny is prone to a command-injection vulnerability.

Attackers can exploit this issue to execute arbitrary commands with root privileges.

Mutiny versions prior to 4.5-1.12 are vulnerable.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))exit(0);
if(!vers =  get_app_version(cpe:CPE, port:port))exit(0);

if (version_is_less(version:vers, test_version:"4.5-1.12")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "4.5-1.12");
  security_message(port:port, data: report);
  exit(0);
}

exit(0);

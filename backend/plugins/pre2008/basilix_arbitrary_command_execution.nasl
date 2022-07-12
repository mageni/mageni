# OpenVAS Vulnerability Test
# $Id: basilix_arbitrary_command_execution.nasl 13976 2019-03-04 09:45:19Z cfischer $
# Description: BasiliX Arbitrary Command Execution Vulnerability
#
# Authors:
# George A. Theall, <theall@tifaware.com>
#
# Copyright:
# Copyright (C) 2004 George A. Theall
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

CPE = "cpe:/a:basilix:basilix_webmail";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14304");
  script_version("$Revision: 13976 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-04 10:45:19 +0100 (Mon, 04 Mar 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_bugtraq_id(3276);
  script_name("BasiliX Arbitrary Command Execution Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2004 George A. Theall");
  script_dependencies("basilix_detect.nasl");
  script_mandatory_keys("basilix/installed");

  script_tag(name:"solution", value:"Upgrade to BasiliX version 1.1.0 or later.");

  script_tag(name:"summary", value:"The remote web server contains a BasiliX PHP script that
  is prone to arbitrary.");

  script_tag(name:"insight", value:"The remote host appears to be running a version of BasiliX
  between 1.0.2beta or 1.0.3beta. In such versions, the script 'login.php3' fails to sanitize user
  input, which enables a remote attacker to pass in a specially crafted value for the parameter
  'username' with arbitrary commands to be executed on the target using the permissions of the web server.");

  script_xref(name:"URL", value:"http://www.derkeiler.com/Mailing-Lists/securityfocus/bugtraq/2001-09/0017.html");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "1.1.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.1.0");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
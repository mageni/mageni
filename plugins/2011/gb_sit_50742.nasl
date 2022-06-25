###############################################################################
# OpenVAS Vulnerability Test
#
# Support Incident Tracker 'translate.php' Remote Code Execution Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103349");
  script_bugtraq_id(50742);
  script_version("2019-05-13T14:05:09+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Support Incident Tracker 'translate.php' Remote Code Execution Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50742");
  script_xref(name:"URL", value:"http://sitracker.sourceforge.net");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/520577");

  script_tag(name:"last_modification", value:"2019-05-13 14:05:09 +0000 (Mon, 13 May 2019)");
  script_tag(name:"creation_date", value:"2011-11-30 11:40:15 +0100 (Wed, 30 Nov 2011)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("support_incident_tracker_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("sit/installed");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"Support Incident Tracker is prone to a remote code-execution
  vulnerability because the application fails to sufficiently sanitize user-supplied input.");

  script_tag(name:"impact", value:"Exploiting this issue will allow attackers to execute arbitrary PHP
  code within the context of the affected application.");

  script_tag(name:"affected", value:"Support Incident Tracker 3.45 to 3.65 is vulnerable. Prior versions
  may also be affected.");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

include("version_func.inc");

port = get_http_port(default:80);

if(vers = get_version_from_kb(port:port,app:"support_incident_tracker")) {
  if(version_in_range(version: vers, test_version: "3.45", test_version2: "3.65")) {
    security_message(port:port);
    exit(0);
  }
}

exit(0);
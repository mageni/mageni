###############################################################################
# OpenVAS Vulnerability Test
# $Id: mldonkey_2_9_7_remote.nasl 13543 2019-02-08 14:43:51Z cfischer $
#
# MLdonkey HTTP Request Arbitrary File Download Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100057");
  script_version("$Revision: 13543 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 15:43:51 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-03-17 18:51:21 +0100 (Tue, 17 Mar 2009)");
  script_bugtraq_id(33865);
  script_cve_id("CVE-2009-0753");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("MLdonkey HTTP Request Arbitrary File Download Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Peer-To-Peer File Sharing");
  script_dependencies("mldonkey_www.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 4080);
  script_mandatory_keys("MLDonkey/www/port/");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33865");

  script_tag(name:"solution", value:"Fixes are available.");

  script_tag(name:"summary", value:"MLdonkey is prone to a vulnerability that lets attackers download arbitrary
  files. The issue occurs because the application fails to sufficiently sanitize
  user-supplied input.");

  script_tag(name:"impact", value:"Exploiting this issue will allow an attacker to view arbitrary files within
  the context of the application. Information harvested may aid in launching further attacks.");

  script_tag(name:"affected", value:"MLdonkey 2.9.7 is vulnerable. Other versions may also be affected.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.nongnu.org/mldonkey/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("misc_func.inc");
include("http_keepalive.inc");

port = get_kb_item("MLDonkey/www/port/");
if(isnull(port))exit(0);

files = traversal_files();

foreach pattern(keys(files)) {

  file = files[pattern];

  url = string("//" + file);
  req = http_get(item:url, port:port);
  buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if(isnull(buf)) continue;

  if( egrep(pattern:pattern, string: buf) ) {
    report = report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

# server allows connections only from localhost by default. So check the version
version = get_kb_item(string("www/", port, "/MLDonkey/version"));
if(isnull(version) || version >< "unknown")exit(0);

if(version <= "2.9.7") {
  info  = string("According to its version number (");
  info += version;
  info += string(") MLDonkey is\nvulnerable, but seems to be reject connections from ");
  info += this_host_name();
  info += string(".\n\n");
  security_message(port:port, data:info);
  exit(0);
}

exit(99);
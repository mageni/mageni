###############################################################################
# OpenVAS Vulnerability Test
#
# Quicksilver Forums Local File Include and Arbitrary File Upload Vulnerabilities
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100504");
  script_version("2019-05-14T12:12:41+0000");
  script_tag(name:"last_modification", value:"2019-05-14 12:12:41 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2010-02-23 17:05:07 +0100 (Tue, 23 Feb 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-7064");
  script_bugtraq_id(32452);
  script_name("Quicksilver Forums Local File Include and Arbitrary File Upload Vulnerabilities");
  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("quicksilver_forums_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("quicksilver/forum/detected", "Host/runs_windows");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"summary", value:"Quicksilver Forums is prone to a local file-include vulnerability and
  an arbitrary-file-upload vulnerability because the application fails
  to sufficiently sanitize user-supplied input.");

  script_tag(name:"impact", value:"An attacker can exploit these issues to upload arbitrary files onto
  the webserver, execute arbitrary local files within the context of the
  webserver, and obtain sensitive information. By exploiting the arbitrary-file-
  upload and local file-include vulnerabilities at the same time, the
  attacker may be able to execute remote code.");

  script_tag(name:"affected", value:"Quicksilver Forums 1.4.2 is vulnerable, other versions may also be
  affected. Note that these issues affect only versions running on
  Windows platforms.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32452");
  script_xref(name:"URL", value:"http://pdnsadmin.iguanadons.net/index.php?a=newspost&t=85");
  script_xref(name:"URL", value:"http://www.quicksilverforums.com/");
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("version_func.inc");

port = get_http_port(default:80);

if(!version = get_kb_item(string("www/", port, "/quicksilver")))
  exit(0);

if(!matches = eregmatch(string:version, pattern:"^(.+) under (/.*)$"))
  exit(0);

vers = matches[1];

if(!isnull(vers) && vers >!< "unknown") {
  if(version_is_less_equal(version: vers, test_version: "1.4.2")) {
    security_message(port:port);
    exit(0);
  }
}

exit(0);

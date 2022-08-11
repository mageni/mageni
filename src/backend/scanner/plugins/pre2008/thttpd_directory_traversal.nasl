###############################################################################
# OpenVAS Vulnerability Test
# $Id: thttpd_directory_traversal.nasl 13975 2019-03-04 09:32:08Z cfischer $
#
# thttpd Directory Traversal (Windows)
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
#
# Copyright:
# Copyright (C) 2004 David Maciejak
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

CPE = "cpe:/a:acme:thttpd";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14229");
  script_version("$Revision: 13975 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-04 10:32:08 +0100 (Mon, 04 Mar 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-2628");
  script_bugtraq_id(10862);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("thttpd Directory Traversal (Windows)");

  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("Remote file access");
  script_dependencies("gb_thttpd_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("thttpd/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"The remote web server is vulnerable to a path traversal vulnerability.");

  script_tag(name:"impact", value:"An attacker may exploit this flaw to read arbitrary files on the remote
system with the privileges of the http process.");

  script_tag(name:"solution", value:"Upgrade your web server or change it.");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

files = traversal_files( "windows" );

foreach file (keys(files)) {
  url = "c:\" + files[file];

  if (http_vuln_check(port: port, url: url, pattern: file, check_header: TRUE)) {
    report = report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);

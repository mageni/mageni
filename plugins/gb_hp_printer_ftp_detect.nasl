# Copyright (C) 2022 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147609");
  script_version("2022-02-08T10:00:44+0000");
  script_tag(name:"last_modification", value:"2022-02-17 11:13:34 +0000 (Thu, 17 Feb 2022)");
  script_tag(name:"creation_date", value:"2022-02-08 05:09:37 +0000 (Tue, 08 Feb 2022)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("HP Printer Detection (FTP)");

  script_tag(name:"summary", value:"FTP based detection of HP printer devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/hp/printer/detected");

  exit(0);
}

include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = ftp_get_port(default: 21);
banner = ftp_get_banner(port: port);

if (banner !~ "^220 (JD )?FTP Server Ready")
  exit(0);

csid = get_kb_item("ftp/fingerprints/" + port + "/csid_banner_authed");
if ((!csid || (csid !~ "PORT\s+HP " && csid !~ "Directory:\s+Description:")) &&
    banner !~ "^220 JD FTP Server Ready")
  exit(0);

help = get_kb_item("ftp/fingerprints/" + port + "/help_banner_authed");

model = "unknown";
fw_version = "unknown";

set_kb_item(name: "hp/printer/detected", value: TRUE);
set_kb_item(name: "hp/printer/ftp/detected", value: TRUE);
set_kb_item(name: "hp/printer/ftp/port", value: port);
if (csid && csid =~ "PORT\s+HP ")
  set_kb_item(name: "hp/printer/ftp/" + port + "/concluded", value: chomp(csid));
else if (help && help =~ "PORT\s+HP ")
  set_kb_item(name: "hp/printer/ftp/" + port + "/concluded", value: chomp(help));
else
  set_kb_item(name: "hp/printer/ftp/" + port + "/concluded", value: banner);

# PORT          HP LaserJet P4515
# PORT          HP LaserJet P3010 Series
# PORT          HP LaserJet 600 M601
if (csid) {
  mod = eregmatch(pattern: 'PORT\\s+HP ([^\r\n]+)', string: csid);
  if (!isnull(mod[1])) {
    model = mod[1];
    model = str_replace(string: model, find: " Series", replace: "");
  }
}

if (model == "unknown" && help) {
  mod = eregmatch(pattern: 'PORT\\s+HP ([^\r\n]+)', string: help);
  if (!isnull(mod[1])) {
    model = mod[1];
    model = str_replace(string: model, find: " Series", replace: "");
  }
}

set_kb_item(name: "hp/printer/ftp/" + port + "/model", value: model);
set_kb_item(name: "hp/printer/ftp/" + port + "/fw_version", value: fw_version);

exit(0);

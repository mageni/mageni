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
  script_oid("1.3.6.1.4.1.25623.1.0.148163");
  script_version("2022-05-24T09:38:49+0000");
  script_tag(name:"last_modification", value:"2022-05-24 09:38:49 +0000 (Tue, 24 May 2022)");
  script_tag(name:"creation_date", value:"2022-05-23 08:29:50 +0000 (Mon, 23 May 2022)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("SurgeMail Detection (IMAP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("imap4_banner.nasl");
  script_mandatory_keys("imap/surgemail/detected");

  script_tag(name:"summary", value:"IMAP based detection of SurgeMail.");

  exit(0);
}

include("imap_func.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = imap_get_port(default: 143);

banner = imap_get_banner(port: port);
capalist = get_kb_list("imap/fingerprints/" + port + "/capalist");

if (egrep(pattern: "surgemail", string: banner, icase: TRUE) ||
    in_array(search: "surgemail", array: capalist, icase: TRUE)) {
  version = "unknown";

  set_kb_item(name: "surgemail/detected", value: TRUE);
  set_kb_item(name: "surgemail/imap/detected", value: TRUE);
  set_kb_item(name: "surgemail/imap/port", value: port);

  # OK IMAP (C) example.com (Version 7.3o4-4)
  vers = eregmatch(pattern: "\(Version ([^)]+)\)", string: banner);
  if (!isnull(vers[1])) {
    version = vers[1];
    set_kb_item(name: "surgemail/imap/" + port + "/concluded", value: banner);
  }

  set_kb_item(name: "surgemail/imap/" + port + "/version", value: version);
}

exit(0);

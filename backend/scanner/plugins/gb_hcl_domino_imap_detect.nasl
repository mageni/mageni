# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.144577");
  script_version("2020-09-16T05:35:44+0000");
  script_tag(name:"last_modification", value:"2020-09-23 10:13:12 +0000 (Wed, 23 Sep 2020)");
  script_tag(name:"creation_date", value:"2020-09-15 09:00:27 +0000 (Tue, 15 Sep 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("HCL / IBM / Lotus Domino Detection (IMAP)");

  script_tag(name:"summary", value:"IMAP based detection of HCL Domino (formerly Lotus/IBM Domino).");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("imap4_banner.nasl");
  script_mandatory_keys("imap/hcl/domino/detected");

  exit(0);
}

include("imap_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = imap_get_port(default: 143);

banner = imap_get_banner(port: port);

if (banner && "Domino IMAP4 Server" >< banner) {
  set_kb_item(name: "hcl/domino/detected", value: TRUE);
  set_kb_item(name: "hcl/domino/imap/port", value: port);
  set_kb_item(name: "hcl/domino/imap/" + port + "/concluded", value: banner);

  version = "unknown";

  # OK Domino IMAP4 Server Release 9.0.1FP10 HF66 ready Tue, 15 Sep 2020 10:13:05 +0200
  # OK Domino IMAP4 Server Release 8.5.3 ready Tue, 15 Sep 2020 01:59:18 -0600
  # OK Domino IMAP4 Server Release 8.5 HF1 ready Tue, 15 Sep 2020 11:49:54 +0300
  vers = eregmatch(pattern: "Domino IMAP4 Server Release ([0-9A-Z.]+[ ]?(HF[0-9]+)?)", string: banner);
  if (!isnull(vers[1])) {
    version = chomp(vers[1]);
    version = str_replace(string: version, find: "FP", replace: ".");
    version = str_replace(string: version, find: " ", replace: ".");
  }

  set_kb_item(name: "hcl/domino/imap/" + port + "/version", value: version);
}

exit(0);

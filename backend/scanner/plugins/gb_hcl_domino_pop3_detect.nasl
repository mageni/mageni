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
  script_oid("1.3.6.1.4.1.25623.1.0.144580");
  script_version("2020-09-16T05:35:44+0000");
  script_tag(name:"last_modification", value:"2020-09-23 10:13:12 +0000 (Wed, 23 Sep 2020)");
  script_tag(name:"creation_date", value:"2020-09-15 09:00:27 +0000 (Tue, 15 Sep 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("HCL / IBM / Lotus Domino Detection (POP3)");

  script_tag(name:"summary", value:"POP3 based detection of HCL Domino (formerly Lotus/IBM Domino).");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("popserver_detect.nasl");
  script_mandatory_keys("pop3/hcl/domino/detected");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("pop3_func.inc");
include("port_service_func.inc");

port = pop3_get_port(default: 110);

banner = pop3_get_banner(port: port);

if (banner && banner =~ "(HCL|Lotus|IBM) Notes POP3 Server") {
  set_kb_item(name: "hcl/domino/detected", value: TRUE);
  set_kb_item(name: "hcl/domino/pop3/port", value: port);
  set_kb_item(name: "hcl/domino/pop3/" + port + "/concluded", value: banner);

  version = "unknown";

  # OK HCL Notes POP3 server version Release 11.0.1 ready on Domino/SitiTarghe/IT.
  # OK IBM Notes POP3 server version Release 9.0.1FP10 HF383 ready on Domino/Aurora.
  # OK Lotus Notes POP3 server version Release 8.5.2 ready on domino/afp.
  vers = eregmatch(pattern: "Release ([0-9A-Z.]+[ ]?(HF[0-9]+)?)", string: banner);
  if (!isnull(vers[1])) {
    version = chomp(vers[1]);
    version = str_replace(string: version, find: "FP", replace: ".");
    version = str_replace(string: version, find: " ", replace: ".");
  }

  set_kb_item(name: "hcl/domino/pop3/" + port + "/version", value: version);
}

exit(0);

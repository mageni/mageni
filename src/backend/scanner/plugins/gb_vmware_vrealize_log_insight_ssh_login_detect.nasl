# Copyright (C) 2016 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105751");
  script_version("2023-02-09T10:17:23+0000");
  script_tag(name:"last_modification", value:"2023-02-09 10:17:23 +0000 (Thu, 09 Feb 2023)");
  script_tag(name:"creation_date", value:"2016-06-10 11:52:17 +0200 (Fri, 10 Jun 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"package");

  script_name("VMware vRealize Log Insight Detection (SSH Login)");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/vmware/vrealize_log_insight/detected");

  script_tag(name:"summary", value:"SSH login-based detection of VMware vRealize Log Insight.");

  exit(0);
}

include("host_details.inc");

port = get_kb_item("ssh/login/vmware/vrealize_log_insight/port");

if (!rls = get_kb_item("ssh/login/vmware/vrealize_log_insight/" + port + "/rls"))
  exit(0);

if (!cmd = get_kb_item("ssh/login/vmware/vrealize_log_insight/" + port + "/rls_cmd"))
  cmd = "unknown";

version = "unknown";
build = "unknown";

set_kb_item(name: "vmware/vrealize_log_insight/detected", value: TRUE);
set_kb_item(name: "vmware/vrealize_log_insight/ssh-login/port", value: port);
set_kb_item(name: "vmware/vrealize_log_insight/ssh-login/" + port + "/concluded", value: rls);
set_kb_item(name: "vmware/vrealize_log_insight/ssh-login/" + port + "/concluded_cmd", value: cmd);

# VMware vRealize Log Insight 3.0.0 Build 3021606
vers = eregmatch(pattern: 'VMware vRealize Log Insight ([0-9]+[^ ]+) Build ([0-9]+[^ \r\n]+)', string: rls);
if (!isnull(vers[1])) {
  version = vers[1];

  if (!isnull(vers[2]))
    build = vers[2];
} else {
  # VMware vRealize Log Insight
  # VERSION=8.4.1
  # BUILD=18136317
  vers = eregmatch(pattern: "VERSION=([0-9.]+)", string: rls);
  if (!isnull(vers[1]))
    version = vers[1];

  bld = eregmatch(pattern: "BUILD=([0-9]+)", string: rls);
  if (!isnull(bld[1]))
    build = bld[1];
}

set_kb_item(name: "vmware/vrealize_log_insight/ssh-login/" + port + "/version", value: version);
set_kb_item(name: "vmware/vrealize_log_insight/ssh-login/" + port + "/build", value: build);

exit(0);

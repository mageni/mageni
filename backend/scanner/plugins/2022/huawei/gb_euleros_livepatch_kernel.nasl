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
  script_oid("1.3.6.1.4.1.25623.1.0.148476");
  script_version("2022-07-19T05:42:50+0000");
  script_tag(name:"last_modification", value:"2022-07-19 05:42:50 +0000 (Tue, 19 Jul 2022)");
  script_tag(name:"creation_date", value:"2022-07-19 04:26:27 +0000 (Tue, 19 Jul 2022)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"package");

  script_name("Huawei EulerOS: Livepatch Status Kernel");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_euleros_hotfix_ssh_login_detect.nasl");
  script_mandatory_keys("euleros/get_hotfix");

  script_tag(name:"summary", value:"Reports the installed HotFixes for the Linux Kernel with their
  corresponding CVE's.");

  script_tag(name:"vuldetect", value:"Checks if HotFixes for the Kernel are applied.");

  exit(0);
}

if (!hotfix = get_kb_item("euleros/get_hotfix"))
  exit(0);

if (!port = get_kb_item("euleros/get_hotfix/port"))
  exit(0);

# "kernel": {
#  "version": "4.19.90-2106.3.0.0095.oe1.x86_64",
#  "CVEs": [
#   "CVE-1111-1111",
#   "CVE-1111-2222"
#  ]
# }
kernel = eregmatch(pattern: '"kernel"\\s*:\\s*([^}]+)', string: hotfix);
if (isnull(kernel[1]))
  exit(0);

cves = eregmatch(pattern: '"CVEs"\\s*:\\s*\\[\\s*"([^]]+)]', string: kernel[1]);
cves = split(chomp(cves[1]));

cve_list = NULL;

for (i = 0; i < max_index(cves); i++) {
  cves[i] = chomp(cves[i]);
  if (cves[i] =~ '^\\s*"?CVE-') {
    if (!isnull(cve_list))
      cve_list += " ";

    cve = ereg_replace(pattern: "^\s*", string: cves[i], replace: "");
    cve_list += str_replace(string: cve, find: '"', replace: "");
  }
}

if (!isnull(cve_list)) {
  report = 'Kernel livepatches for the following CVE(s) have been applied:\n\n' + cve_list;
  log_message(port: port, data: report);
  exit(0);
}

exit(0);

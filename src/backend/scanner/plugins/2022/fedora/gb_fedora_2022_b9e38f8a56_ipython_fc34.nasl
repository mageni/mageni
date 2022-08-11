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
  script_oid("1.3.6.1.4.1.25623.1.0.819741");
  script_version("2022-02-22T09:18:02+0000");
  script_cve_id("CVE-2022-21699");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-02-22 11:21:00 +0000 (Tue, 22 Feb 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-26 17:53:00 +0000 (Wed, 26 Jan 2022)");
  script_tag(name:"creation_date", value:"2022-02-12 02:03:07 +0000 (Sat, 12 Feb 2022)");
  script_name("Fedora: Security Advisory for ipython (FEDORA-2022-b9e38f8a56)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC34");

  script_xref(name:"Advisory-ID", value:"FEDORA-2022-b9e38f8a56");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/DZ7LVZBB4D7KVSFNEQUBEHFO3JW6D2ZK");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ipython'
  package(s) announced via the FEDORA-2022-b9e38f8a56 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"IPython provides a replacement for the interactive Python interpreter with
extra functionality.

Main features:

  * Comprehensive object introspection.

  * Input history, persistent across sessions.

  * Caching of output results during a session with automatically generated
   references.

  * Readline based name completion.

  * Extensible system of &#39, magic&#39, commands for controlling the environment and
   performing many tasks related either to IPython or the operating system.

  * Configuration system with easy switching between different setups (simpler
   than changing $PYTHONSTARTUP environment variables every time).

  * Session logging and reloading.

  * Extensible syntax processing for special purpose situations.

  * Access to the system shell with user-extensible alias system.

  * Easily embeddable in other Python programs.

  * Integrated access to the pdb debugger and the Python profiler.");

  script_tag(name:"affected", value:"'ipython' package(s) on Fedora 34.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "FC34") {

  if(!isnull(res = isrpmvuln(pkg:"ipython", rpm:"ipython~7.20.0~2.fc34", rls:"FC34"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
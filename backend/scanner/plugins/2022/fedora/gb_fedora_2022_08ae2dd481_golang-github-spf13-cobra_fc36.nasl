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
  script_oid("1.3.6.1.4.1.25623.1.0.820423");
  script_version("2022-05-23T14:06:16+0000");
  script_cve_id("CVE-2022-27191");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-05-23 14:06:16 +0000 (Mon, 23 May 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-25 17:15:00 +0000 (Fri, 25 Mar 2022)");
  script_tag(name:"creation_date", value:"2022-05-08 01:10:51 +0000 (Sun, 08 May 2022)");
  script_name("Fedora: Security Advisory for golang-github-spf13-cobra (FEDORA-2022-08ae2dd481)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC36");

  script_xref(name:"Advisory-ID", value:"FEDORA-2022-08ae2dd481");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/T7DUXLX5ISUPSME7NS6KBKRYLDOGVH6P");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'golang-github-spf13-cobra'
  package(s) announced via the FEDORA-2022-08ae2dd481 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Cobra is a library providing a simple interface to create powerful modern CLI
interfaces similar to git & go tools.

Cobra is also an application that will generate your application scaffolding to
rapidly develop a Cobra-based application.

Cobra provides:

  - Easy subcommand-based CLIs: app server, app fetch, etc.

  - Fully POSIX-compliant flags (including short & long versions)

  - Nested subcommands

  - Global, local and cascading flags

  - Easy generation of applications & commands with cobra init appname & cobra
   add cmdname

  - Intelligent suggestions (app srver... did you mean app server?)

  - Automatic help generation for commands and flags

  - Automatic help flag recognition of -h, --help, etc.

  - Automatically generated bash autocomplete for your application

  - Automatically generated man pages for your application

  - Command aliases so you can change things without breaking them

  - The flexibility to define your own help, usage, etc.

  - Optional tight integration with viper for 12-factor apps");

  script_tag(name:"affected", value:"'golang-github-spf13-cobra' package(s) on Fedora 36.");

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

if(release == "FC36") {

  if(!isnull(res = isrpmvuln(pkg:"golang-github-spf13-cobra", rpm:"golang-github-spf13-cobra~1.4.0~2.fc36", rls:"FC36"))) {
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
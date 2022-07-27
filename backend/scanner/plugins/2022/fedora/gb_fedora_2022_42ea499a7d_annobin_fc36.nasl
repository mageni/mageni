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
  script_oid("1.3.6.1.4.1.25623.1.0.819878");
  script_version("2022-03-23T08:34:11+0000");
  # TODO: No CVE assigned yet.
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-03-23 08:34:11 +0000 (Wed, 23 Mar 2022)");
  script_tag(name:"creation_date", value:"2022-03-23 08:34:11 +0000 (Wed, 23 Mar 2022)");
  script_name("Fedora: Security Advisory for annobin (FEDORA-2022-42ea499a7d)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC36");

  script_xref(name:"Advisory-ID", value:"FEDORA-2022-42ea499a7d");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/SP7C437YQDRDH3MFRU7JB2LSKQCPOQH7");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'annobin'
  package(s) announced via the FEDORA-2022-42ea499a7d advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This package contains the tools needed to annotate binary files created by
compilers, and also the tools needed to examine those annotations.


One of the tools is a plugin for GCC that records information about the
security options that were in effect when the binary was compiled.

Note - the plugin is automatically enabled in gcc builds via flags
provided by the redhat-rpm-macros package.



One of the tools is a plugin for Clang that records information about the
security options that were in effect when the binary was compiled.



One of the tools is a plugin for LLVM that records information about the
security options that were in effect when the binary was compiled.



One of the tools is a security checker which analyses the notes present in
annotated files and reports on any missing security options.");

  script_tag(name:"affected", value:"'annobin' package(s) on Fedora 36.");

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

  if(!isnull(res = isrpmvuln(pkg:"annobin", rpm:"annobin~10.57~3.fc36", rls:"FC36"))) {
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
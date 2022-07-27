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
  script_oid("1.3.6.1.4.1.25623.1.0.878564");
  script_version("2020-11-06T08:04:05+0000");
  script_cve_id("CVE-2020-2026");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-11-06 11:47:26 +0000 (Fri, 06 Nov 2020)");
  script_tag(name:"creation_date", value:"2020-11-05 04:17:51 +0000 (Thu, 05 Nov 2020)");
  script_name("Fedora: Security Advisory for kata-ksm-throttler (FEDORA-2020-15a1bde727)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC31");

  script_xref(name:"FEDORA", value:"2020-15a1bde727");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/2P7FHA4AF6Y6PAVJBTTQPUEHXZQUOF3P");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kata-ksm-throttler'
  package(s) announced via the FEDORA-2020-15a1bde727 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This project implements a Kernel Same-page Merging throttling daemon.

The Kata Containers runtime creates a virtual machine (VM) to isolate
a set of container workloads. The VM requires a guest kernel and a
guest operating system ('guest OS') to boot and create containers
inside the guest environment. This package contains the tools to create
guest OS images.

The goal of the ksm throttler daemon is to regulate KSM by dynamically
modifying the KSM sysfs entries, in order to minimize memory
duplication as fast as possible while keeping the KSM daemon load low.");

  script_tag(name:"affected", value:"'kata-ksm-throttler' package(s) on Fedora 31.");

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

if(release == "FC31") {

  if(!isnull(res = isrpmvuln(pkg:"kata-ksm-throttler", rpm:"kata-ksm-throttler~1.11.1~1.fc31.1", rls:"FC31"))) {
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
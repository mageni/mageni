# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.823160");
  script_version("2023-01-26T10:11:56+0000");
  script_cve_id("CVE-2021-3638", "CVE-2022-4144");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-01-26 10:11:56 +0000 (Thu, 26 Jan 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-15 12:57:00 +0000 (Tue, 15 Mar 2022)");
  script_tag(name:"creation_date", value:"2023-01-20 02:06:24 +0000 (Fri, 20 Jan 2023)");
  script_name("Fedora: Security Advisory for qemu (FEDORA-2023-c8a60f6f80)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC36");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-c8a60f6f80");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/GTVPHLLXJ65BUMFBUUZ35F3J632SLFRK");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu'
  package(s) announced via the FEDORA-2023-c8a60f6f80 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"qemu is an open source virtualizer that provides hardware
emulation for the KVM hypervisor. qemu acts as a virtual
machine monitor together with the KVM kernel modules, and emulates the
hardware for a full system such as a PC and its associated peripherals.");

  script_tag(name:"affected", value:"'qemu' package(s) on Fedora 36.");

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

  if(!isnull(res = isrpmvuln(pkg:"qemu", rpm:"qemu~6.2.0~17.fc36", rls:"FC36"))) {
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
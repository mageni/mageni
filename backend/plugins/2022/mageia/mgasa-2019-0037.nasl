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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0037");
  script_cve_id("CVE-2018-15126", "CVE-2018-15127", "CVE-2018-20019", "CVE-2018-20020", "CVE-2018-20021", "CVE-2018-20022", "CVE-2018-20023", "CVE-2018-20024", "CVE-2018-6307");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-31 01:15:00 +0000 (Thu, 31 Oct 2019)");

  script_name("Mageia: Security Advisory (MGASA-2019-0037)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0037");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0037.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=24177");
  script_xref(name:"URL", value:"https://github.com/LibVNC/libvncserver/releases/tag/LibVNCServer-0.9.12");
  script_xref(name:"URL", value:"https://github.com/LibVNC/x11vnc/releases/tag/0.9.15");
  script_xref(name:"URL", value:"https://github.com/LibVNC/x11vnc/releases/tag/0.9.16");
  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2018/12/msg00017.html");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2019-01/msg00027.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libvncserver, x11vnc' package(s) announced via the MGASA-2019-0037 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A heap use-after-free vulnerability in the server code of the file
transfer extension, which can result in remote code execution. This
attack appears to be exploitable via network connectivity
(CVE-2018-6307).

A heap use-after-free vulnerability in the server code of the file
transfer extension, which can result in remote code execution. This
attack appears to be exploitable via network connectivity
(CVE-2018-15126).

A heap out-of-bound write vulnerability in the server code of the file
transfer extension, which can result in remote code execution. This
attack appears to be exploitable via network connectivity
(CVE-2018-15127).

Multiple heap out-of-bound write vulnerabilities in VNC client code,
which can result in remote code execution (CVE-2018-20019).

Heap out-of-bound write vulnerability in a structure in VNC client code,
which can result in remote code execution (CVE-2018-20020).

Infinite Loop vulnerability in VNC client code. The vulnerability could
allow an attacker to consume an excessive amount of resources, such as
CPU and RAM (CVE-2018-20021).

Improper Initialization weaknesses in VNC client code, which could allow
an attacker to read stack memory and can be abused for information
disclosure. Combined with another vulnerability, it can be used to leak
stack memory layout and bypass ASLR (CVE-2018-20022).

Improper Initialization vulnerability in VNC Repeater client code, which
could allow an attacker to read stack memory and can be abused for
information disclosure. Combined with another vulnerability, it can be
used to leak stack memory layout and bypass ASLR (CVE-2018-20023).

A null pointer dereference in VNC client code, which can result in DoS
(CVE-2018-20024).");

  script_tag(name:"affected", value:"'libvncserver, x11vnc' package(s) on Mageia 6.");

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

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"lib64vncserver-devel", rpm:"lib64vncserver-devel~0.9.12~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64vncserver1", rpm:"lib64vncserver1~0.9.12~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvncserver", rpm:"libvncserver~0.9.12~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvncserver-devel", rpm:"libvncserver-devel~0.9.12~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvncserver1", rpm:"libvncserver1~0.9.12~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"x11vnc", rpm:"x11vnc~0.9.16~1.mga6", rls:"MAGEIA6"))) {
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

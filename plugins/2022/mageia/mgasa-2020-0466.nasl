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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0466");
  script_cve_id("CVE-2020-14872", "CVE-2020-14881", "CVE-2020-14884", "CVE-2020-14885", "CVE-2020-14886", "CVE-2020-14889", "CVE-2020-14892");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-22 19:39:00 +0000 (Mon, 22 Feb 2021)");

  script_name("Mageia: Security Advisory (MGASA-2020-0466)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0466");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0466.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=27479");
  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpuoct2020.html#AppendixOVIR");
  script_xref(name:"URL", value:"https://www.virtualbox.org/wiki/Changelog-6.1#v16");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kmod-virtualbox, virtualbox' package(s) announced via the MGASA-2020-0466 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Vulnerabilities in the Oracle VM VirtualBox are fixed in version 6.1.16.

An attacker must first obtain the ability to execute high-privileged code on
the target guest system in order to exploit this vulnerability which can lead
to execute code in the context of the hypervisor. (CVE-2020-14872).

An attacker must first obtain the ability to execute high-privileged code on
the target guest system in order to exploit this vulnerability.
The specific flaw exists within the shader_generate_main function. The issue
results from the lack of proper validation of user-supplied data, which can
result in a read past the end of an allocated buffer. An attacker can
leverage this in conjunction with other vulnerabilities to execute code in
the context of the hypervisor. (CVE-2020-14881).

An attacker must first obtain the ability to execute high-privileged code on
the target guest system in order to exploit this vulnerability.
The specific flaw exists within the shader_record_register_usage function.
The issue results from the lack of proper validation of user-supplied data,
which can result in a type confusion condition. An attacker can leverage
this in conjunction with other vulnerabilities to execute code in the context
of the hypervisor. (CVE-2020-14884).

An attacker must first obtain the ability to execute high-privileged code on
the target guest system in order to exploit this vulnerability. The specific
flaw exists within the shader_generate_main function. The issue results from
the lack of proper validation of user-supplied data, which can result in a
read past the end of an allocated buffer. An attacker can leverage this in
conjunction with other vulnerabilities to execute code in the context of the
hypervisor. (CVE-2020-14885).

An attacker must first obtain the ability to execute high-privileged code on
the target guest system in order to exploit this vulnerability.
The specific flaw exists within the shader_skip_unrecognized function. The
issue results from the lack of proper validation of user-supplied data, which
can result in a read past the end of an allocated buffer. An attacker can
leverage this in conjunction with other vulnerabilities to execute code in
the context of the hypervisor. (CVE-2020-14886).

An attacker must first obtain the ability to execute high-privileged code on
the target guest system in order to exploit this vulnerability which can
result in unauthorized access to critical data or complete access to all
Oracle VM VirtualBox accessible data. (CVE-2020-14889).

An attacker must first obtain the ability to execute high-privileged code on
the target guest system in order to exploit this vulnerability which result
in unauthorized ability to cause a hang or frequently repeatable crash
(complete DOS) of Oracle VM VirtualBox. (CVE-2020-14892).

Also this updated version has some bugfix (See upstream Changelog).");

  script_tag(name:"affected", value:"'kmod-virtualbox, virtualbox' package(s) on Mageia 7.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"dkms-vboxadditions", rpm:"dkms-vboxadditions~6.1.16~4.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dkms-virtualbox", rpm:"dkms-virtualbox~6.1.16~4.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-virtualbox", rpm:"kmod-virtualbox~6.1.16~4.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-virtualbox", rpm:"python-virtualbox~6.1.16~4.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox", rpm:"virtualbox~6.1.16~4.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-devel", rpm:"virtualbox-devel~6.1.16~4.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-additions", rpm:"virtualbox-guest-additions~6.1.16~4.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-5.7.19-desktop-3.mga7", rpm:"virtualbox-kernel-5.7.19-desktop-3.mga7~6.1.16~4.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-5.7.19-server-3.mga7", rpm:"virtualbox-kernel-5.7.19-server-3.mga7~6.1.16~4.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-desktop-latest", rpm:"virtualbox-kernel-desktop-latest~6.1.16~4.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-server-latest", rpm:"virtualbox-kernel-server-latest~6.1.16~4.mga7", rls:"MAGEIA7"))) {
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

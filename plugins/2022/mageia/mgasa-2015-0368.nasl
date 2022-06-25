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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0368");
  script_cve_id("CVE-2015-5165", "CVE-2015-5239", "CVE-2015-6815", "CVE-2015-6855");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-15 17:05:00 +0000 (Wed, 15 Dec 2021)");

  script_name("Mageia: Security Advisory (MGASA-2015-0368)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0368");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0368.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=16604");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2015-September/165305.html");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2015/09/02/7");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2015/09/05/5");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2015/09/10/2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu' package(s) announced via the MGASA-2015-0368 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated qemu packages fix security vulnerabilities:

Qemu emulator built with the RTL8139 emulation support is vulnerable to an
information leakage flaw. It could occur while processing network packets
under RTL8139 controller's C+ mode of operation. A guest user could use this
flaw to read uninitialised Qemu heap memory up to 65K bytes (CVE-2015-5165).

Qemu emulator built with the VNC display driver is vulnerable to an infinite
loop issue. It could occur while processing a CLIENT_CUT_TEXT message with
specially crafted payload message. A privileged guest user could use this flaw
to crash the Qemu process on the host, resulting in DoS (CVE-2015-5239).

Qemu emulator built with the e1000 NIC emulation support is vulnerable to an
infinite loop issue. It could occur while processing transmit descriptor data
when sending a network packet. A privileged user inside guest could use this
flaw to crash the Qemu instance resulting in DoS (CVE-2015-6815).

Qemu emulator built with the IDE disk and CD/DVD-ROM emulation support is
vulnerable to a divide by zero issue. It could occur while executing an IDE
command WIN_READ_NATIVE_MAX to determine the maximum size of a drive. A
privileged user inside guest could use this flaw to crash the Qemu instance
resulting in DoS (CVE-2015-6855).");

  script_tag(name:"affected", value:"'qemu' package(s) on Mageia 4.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"qemu", rpm:"qemu~1.6.2~1.16.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~1.6.2~1.16.mga4", rls:"MAGEIA4"))) {
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

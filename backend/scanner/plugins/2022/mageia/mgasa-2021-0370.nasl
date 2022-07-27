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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0370");
  script_cve_id("CVE-2021-21341", "CVE-2021-21342", "CVE-2021-21343", "CVE-2021-21344", "CVE-2021-21345", "CVE-2021-21346", "CVE-2021-21347", "CVE-2021-21348", "CVE-2021-21349", "CVE-2021-21350", "CVE-2021-21351", "CVE-2021-29505");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0370)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0370");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0370.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=28844");
  script_xref(name:"URL", value:"https://access.redhat.com/errata/RHSA-2021:1354");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2021/dla-2616");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4943-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/H2CFEJOW6N5BGEB6UU3SEQ3UF5C2UWJL/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xstream' package(s) announced via the MGASA-2021-0370 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In XStream before version 1.4.16, there is a vulnerability which may allow a
remote attacker to allocate 100% CPU time on the target system depending on
CPU type or parallel execution of such a payload resulting in a denial of
service only by manipulating the processed input stream (CVE-2021-21341).

In XStream before version 1.4.16, there is a vulnerability where the processed
stream at unmarshalling time contains type information to recreate the
formerly written objects. XStream creates therefore new instances based on
these type information. An attacker can manipulate the processed input stream
and replace or inject objects, that result in a server-side forgery request
(CVE-2021-21342).

In XStream before version 1.4.16, there is a vulnerability where the processed
stream at unmarshalling time contains type information to recreate the formerly
written objects. XStream creates therefore new instances based on these type
information. An attacker can manipulate the processed input stream and replace
or inject objects, that result in the deletion of a file on the local host
(CVE-2021-21343).

In XStream before version 1.4.16, there is a vulnerability which may allow a
remote attacker to load and execute arbitrary code from a remote host only by
manipulating the processed input stream (CVE-2021-21344).

In XStream before version 1.4.16, there is a vulnerability which may allow a
remote attacker who has sufficient rights to execute commands of the host only
by manipulating the processed input stream (CVE-2021-21345).

In XStream before version 1.4.16, there is a vulnerability which may allow a
remote attacker to load and execute arbitrary code from a remote host only by
manipulating the processed input stream (CVE-2021-21346).

In XStream before version 1.4.16, there is a vulnerability which may allow a
remote attacker to load and execute arbitrary code from a remote host only by
manipulating the processed input stream (CVE-2021-21347).

In XStream before version 1.4.16, there is a vulnerability which may allow a
remote attacker to occupy a thread that consumes maximum CPU time and will
never return (CVE-2021-21348).

In XStream before version 1.4.16, there is a vulnerability which may allow a
remote attacker to request data from internal resources that are not publicly
available only by manipulating the processed input stream (CVE-2021-21349).

In XStream before version 1.4.16, there is a vulnerability which may allow a
remote attacker to execute arbitrary code only by manipulating the processed
input stream (CVE-2021-21350).

In XStream before version 1.4.16, there is a vulnerability which may allow a
remote attacker to load and execute arbitrary code from a remote host only by
manipulating the processed input stream (CVE-2021-21351).

A vulnerability in XStream versions prior to 1.4.17 may allow a remote attacker
has sufficient rights to execute commands of the host only ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'xstream' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"xstream", rpm:"xstream~1.4.15~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xstream-benchmark", rpm:"xstream-benchmark~1.4.15~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xstream-javadoc", rpm:"xstream-javadoc~1.4.15~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xstream-parent", rpm:"xstream-parent~1.4.15~1.1.mga8", rls:"MAGEIA8"))) {
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

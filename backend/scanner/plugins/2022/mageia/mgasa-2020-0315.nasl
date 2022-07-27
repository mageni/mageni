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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0315");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"Greenbone");
  script_tag(name:"severity_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");

  script_name("Mageia: Security Advisory (MGASA-2020-0315)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0315");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0315.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=26746");
  script_xref(name:"URL", value:"https://github.com/mumble-voip/mumble/issues/4219");
  script_xref(name:"URL", value:"https://github.com/mumble-voip/mumble/pull/4227");
  script_xref(name:"URL", value:"https://eprint.iacr.org/2019/311");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mumble' package(s) announced via the MGASA-2020-0315 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated mumble package fixes security vulnerability:


OCB2 is known to be broken under certain conditions:
[link moved to references]

To execute the universal attacks described in the paper, an attacker
needs access to an encryption oracle that allows it to perform encryption
queries with attacker-chosen nonce. Luckily in Mumble the encryption nonce
is a fixed counter which is far too restrictive for the universal attacks
to be feasible against Mumble.

The basic attacks do not require an attacker-chosen nonce and as such are
more applicable to Mumble. They are however of limited use and do require
an en- and a decryption oracle which Mumble seemingly does not provide at
the same time.

To be on the safe side, this commit implements the counter-cryptanalysis
measure described in the paper in section 9 for the sender and receiver side.
This way if either server of client are patched, their communication is almost
certainly (merely lacking formal proof) not susceptible to the attacks described
in the paper.


Fixed: Potential exploit in the OCB2 encryption (#4227)");

  script_tag(name:"affected", value:"'mumble' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"mumble", rpm:"mumble~1.3.2~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mumble-plugins", rpm:"mumble-plugins~1.3.2~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mumble-protocol-plasma5", rpm:"mumble-protocol-plasma5~1.3.2~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mumble-server", rpm:"mumble-server~1.3.2~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mumble-server-web", rpm:"mumble-server-web~1.3.2~1.mga7", rls:"MAGEIA7"))) {
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

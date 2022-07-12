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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0494");
  script_cve_id("CVE-2018-19044", "CVE-2018-19045", "CVE-2018-19046", "CVE-2018-19115");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_name("Mageia: Security Advisory (MGASA-2018-0494)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0494");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0494.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=24063");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/6YQ7NS6S7B7V2X5NEUJKMTNXL3YPD7H3/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'keepalived' package(s) announced via the MGASA-2018-0494 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"keepalived before version 2.0.9 didn't check for pathnames with symlinks
when writing data to a temporary file upon a call to PrintData or
PrintStats. This allowed local users to overwrite arbitrary files if
fs.protected_symlinks is set to 0, as demonstrated by a symlink from
/tmp/keepalived.data or /tmp/keepalived.stats to /etc/passwd
(CVE-2018-19044).

keepalived before version 2.0.9 used mode 0666 when creating new
temporary files upon a call to PrintData or PrintStats, potentially
leaking sensitive information (CVE-2018-19045).

keepalived before version 2.0.10 didn't check for existing plain files
when writing data to a temporary file upon a call to PrintData or
PrintStats. If a local attacker had previously created a file with the
expected name (e.g., /tmp/keepalived.data or /tmp/keepalived.stats),
with read access for the attacker and write access for the keepalived
process, then this potentially leaked sensitive information
(CVE-2018-19046).

keepalived before version 2.0.9 has a heap-based buffer overflow when
parsing HTTP status codes resulting in DoS or possibly unspecified other
impact, because extract_status_code in lib/html.c has no validation of
the status code and instead writes an unlimited amount of data to the
heap (CVE-2018-19115).");

  script_tag(name:"affected", value:"'keepalived' package(s) on Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"keepalived", rpm:"keepalived~2.0.10~1.mga6", rls:"MAGEIA6"))) {
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

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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0077");
  script_cve_id("CVE-2019-19905", "CVE-2020-5209", "CVE-2020-5210", "CVE-2020-5211", "CVE-2020-5212", "CVE-2020-5213", "CVE-2020-5214", "CVE-2020-5254");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-27 18:00:00 +0000 (Fri, 27 Dec 2019)");

  script_name("Mageia: Security Advisory (MGASA-2021-0077)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0077");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0077.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=26228");
  script_xref(name:"URL", value:"https://nethack.org/v362/release.html");
  script_xref(name:"URL", value:"https://nethack.org/v363/release.html");
  script_xref(name:"URL", value:"https://nethack.org/v364/release.html");
  script_xref(name:"URL", value:"https://nethack.org/v365/release.html");
  script_xref(name:"URL", value:"https://nethack.org/v366/release.html");
  script_xref(name:"URL", value:"https://www.nethack.org/security/CVE-2019-19905.html");
  script_xref(name:"URL", value:"https://www.nethack.org/security/CVE-2020-5209.html");
  script_xref(name:"URL", value:"https://www.nethack.org/security/CVE-2020-5210.html");
  script_xref(name:"URL", value:"https://www.nethack.org/security/CVE-2020-5211.html");
  script_xref(name:"URL", value:"https://www.nethack.org/security/CVE-2020-5212.html");
  script_xref(name:"URL", value:"https://www.nethack.org/security/CVE-2020-5213.html");
  script_xref(name:"URL", value:"https://www.nethack.org/security/CVE-2020-5214.html");
  script_xref(name:"URL", value:"https://www.nethack.org/security/CVE-2020-5254.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nethack' package(s) announced via the MGASA-2021-0077 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated nethack packages fix security vulnerabilities:

NetHack 3.6.x before 3.6.4 is prone to a buffer overflow vulnerability when
reading very long lines from configuration files. This affects systems that
have NetHack installed suid/sgid, and shared systems that allow users to
upload their own configuration files (CVE-2019-19905).

In NetHack before 3.6.5, unknown options starting with -de and -i can cause
a buffer overflow resulting in a crash or remote code execution/privilege
escalation. This vulnerability affects systems that have NetHack installed
suid/sgid and shared systems that allow users to influence command line
options (CVE-2020-5209).

In NetHack before 3.6.5, an invalid argument to the -w command line option
can cause a buffer overflow resulting in a crash or remote code
execution/privilege escalation. This vulnerability affects systems that have
NetHack installed suid/sgid and shared systems that allow users to influence
command line options (CVE-2020-5210).

In NetHack before 3.6.5, an invalid extended command in value for the
AUTOCOMPLETE configuration file option can cause a buffer overflow resulting
in a crash or remote code execution/privilege escalation. This vulnerability
affects systems that have NetHack installed suid/sgid and shared systems
that allow users to upload their own configuration files (CVE-2020-5211).

In NetHack before 3.6.5, an extremely long value for the MENUCOLOR
configuration file option can cause a buffer overflow resulting in a crash
or remote code execution/privilege escalation. This vulnerability affects
systems that have NetHack installed suid/sgid and shared systems that allow
users to upload their own configuration files (CVE-2020-5212).

In NetHack before 3.6.5, too long of a value for the SYMBOL configuration
file option can cause a buffer overflow resulting in a crash or remote code
execution/privilege escalation. This vulnerability affects systems that have
NetHack installed suid/sgid and shared systems that allow users to upload
their own configuration files (CVE-2020-5213).

In NetHack before 3.6.5, detecting an unknown configuration file option can
cause a buffer overflow resulting in a crash or remote code
execution/privilege escalation. This vulnerability affects systems that have
NetHack installed suid/sgid and shared systems that allow users to upload
their own configuration files (CVE-2020-5214).

In NetHack before 3.6.6, some out-of-bound values for the hilite_status
option can be exploited (CVE-2020-5254).

The nethack package has been updated to version 3.6.6, fixing these issues
and other bugs. See the upstream release notes for details.");

  script_tag(name:"affected", value:"'nethack' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"nethack", rpm:"nethack~3.6.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nethack-bitmap-fonts", rpm:"nethack-bitmap-fonts~3.6.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nethack-bitmap-fonts-core", rpm:"nethack-bitmap-fonts-core~3.6.6~1.mga7", rls:"MAGEIA7"))) {
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

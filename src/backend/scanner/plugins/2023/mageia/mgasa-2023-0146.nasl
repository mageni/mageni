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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0146");
  script_cve_id("CVE-2023-1945", "CVE-2023-1999", "CVE-2023-29533", "CVE-2023-29535", "CVE-2023-29536", "CVE-2023-29539", "CVE-2023-29541", "CVE-2023-29550");
  script_tag(name:"creation_date", value:"2023-04-17 04:13:02 +0000 (Mon, 17 Apr 2023)");
  script_version("2023-04-18T10:10:05+0000");
  script_tag(name:"last_modification", value:"2023-04-18 10:10:05 +0000 (Tue, 18 Apr 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2023-0146)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0146");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0146.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31783");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2023-14/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox, firefox-l10n, libwebp' package(s) announced via the MGASA-2023-0146 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated firefox and libwebp packages fix security vulnerabilities:

Unexpected data returned from the Safe Browsing API could have led to memory
corruption and a potentially exploitable crash (CVE-2023-1945).

A website could have obscured the fullscreen notification by using a
combination of window.open, fullscreen requests, window.name assignments, and
setInterval calls. This could have led to user confusion and possible spoofing
attacks (CVE-2023-29533).

Following a Garbage Collector compaction, weak maps may have been accessed
before they were correctly traced. This resulted in memory corruption and a
potentially exploitable crash (CVE-2023-29535).

An attacker could, via JavaScript code, cause the memory manager to
incorrectly free a pointer that addresses attacker-controlled memory,
resulting in an assertion, memory corruption, or a potentially exploitable
crash (CVE-2023-29536).

When handling the filename directive in the Content-Disposition header, the
filename would be truncated if the filename contained a NULL character. This
could have led to reflected file download attacks potentially tricking users
to install malware (CVE-2023-29539).

Firefox did not properly handle downloads of files ending in .desktop, which
can be interpreted to run attacker-controlled commands (CVE-2023-29541).

Mozilla developers Andrew Osmond, Sebastian Hengst, Andrew McCreight, and the
Mozilla Fuzzing Team reported memory safety bugs present in Firefox ESR 102.9.
Some of these bugs showed evidence of memory corruption and we presume that
with enough effort some of these could have been exploited to run arbitrary
code (CVE-2023-29550).

A double-free in libwebp could have led to memory corruption and a
potentially exploitable crash (CVE-2023-1999).");

  script_tag(name:"affected", value:"'firefox, firefox-l10n, libwebp' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"firefox", rpm:"firefox~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-af", rpm:"firefox-af~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-an", rpm:"firefox-an~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ar", rpm:"firefox-ar~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ast", rpm:"firefox-ast~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-az", rpm:"firefox-az~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-be", rpm:"firefox-be~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-bg", rpm:"firefox-bg~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-bn", rpm:"firefox-bn~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-br", rpm:"firefox-br~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-bs", rpm:"firefox-bs~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ca", rpm:"firefox-ca~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-cs", rpm:"firefox-cs~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-cy", rpm:"firefox-cy~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-da", rpm:"firefox-da~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-de", rpm:"firefox-de~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-el", rpm:"firefox-el~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-en_CA", rpm:"firefox-en_CA~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-en_GB", rpm:"firefox-en_GB~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-en_US", rpm:"firefox-en_US~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-eo", rpm:"firefox-eo~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-es_AR", rpm:"firefox-es_AR~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-es_CL", rpm:"firefox-es_CL~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-es_ES", rpm:"firefox-es_ES~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-es_MX", rpm:"firefox-es_MX~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-et", rpm:"firefox-et~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-eu", rpm:"firefox-eu~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-fa", rpm:"firefox-fa~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ff", rpm:"firefox-ff~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-fi", rpm:"firefox-fi~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-fr", rpm:"firefox-fr~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-fy_NL", rpm:"firefox-fy_NL~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ga_IE", rpm:"firefox-ga_IE~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-gd", rpm:"firefox-gd~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-gl", rpm:"firefox-gl~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-gu_IN", rpm:"firefox-gu_IN~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-he", rpm:"firefox-he~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-hi_IN", rpm:"firefox-hi_IN~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-hr", rpm:"firefox-hr~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-hsb", rpm:"firefox-hsb~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-hu", rpm:"firefox-hu~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-hy_AM", rpm:"firefox-hy_AM~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ia", rpm:"firefox-ia~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-id", rpm:"firefox-id~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-is", rpm:"firefox-is~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-it", rpm:"firefox-it~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ja", rpm:"firefox-ja~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ka", rpm:"firefox-ka~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-kab", rpm:"firefox-kab~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-kk", rpm:"firefox-kk~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-km", rpm:"firefox-km~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-kn", rpm:"firefox-kn~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ko", rpm:"firefox-ko~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-l10n", rpm:"firefox-l10n~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-lij", rpm:"firefox-lij~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-lt", rpm:"firefox-lt~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-lv", rpm:"firefox-lv~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-mk", rpm:"firefox-mk~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-mr", rpm:"firefox-mr~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ms", rpm:"firefox-ms~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-my", rpm:"firefox-my~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-nb_NO", rpm:"firefox-nb_NO~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-nl", rpm:"firefox-nl~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-nn_NO", rpm:"firefox-nn_NO~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-oc", rpm:"firefox-oc~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-pa_IN", rpm:"firefox-pa_IN~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-pl", rpm:"firefox-pl~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-pt_BR", rpm:"firefox-pt_BR~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-pt_PT", rpm:"firefox-pt_PT~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ro", rpm:"firefox-ro~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ru", rpm:"firefox-ru~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-si", rpm:"firefox-si~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-sk", rpm:"firefox-sk~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-sl", rpm:"firefox-sl~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-sq", rpm:"firefox-sq~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-sr", rpm:"firefox-sr~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-sv_SE", rpm:"firefox-sv_SE~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-szl", rpm:"firefox-szl~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ta", rpm:"firefox-ta~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-te", rpm:"firefox-te~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-th", rpm:"firefox-th~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-tl", rpm:"firefox-tl~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-tr", rpm:"firefox-tr~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-uk", rpm:"firefox-uk~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ur", rpm:"firefox-ur~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-uz", rpm:"firefox-uz~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-vi", rpm:"firefox-vi~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-xh", rpm:"firefox-xh~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-zh_CN", rpm:"firefox-zh_CN~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-zh_TW", rpm:"firefox-zh_TW~102.10.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64webp-devel", rpm:"lib64webp-devel~1.1.0~2.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64webp7", rpm:"lib64webp7~1.1.0~2.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64webpdecoder3", rpm:"lib64webpdecoder3~1.1.0~2.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64webpdemux2", rpm:"lib64webpdemux2~1.1.0~2.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64webpmux3", rpm:"lib64webpmux3~1.1.0~2.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebp", rpm:"libwebp~1.1.0~2.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebp-devel", rpm:"libwebp-devel~1.1.0~2.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebp-tools", rpm:"libwebp-tools~1.1.0~2.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebp7", rpm:"libwebp7~1.1.0~2.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpdecoder3", rpm:"libwebpdecoder3~1.1.0~2.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpdemux2", rpm:"libwebpdemux2~1.1.0~2.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpmux3", rpm:"libwebpmux3~1.1.0~2.1.mga8", rls:"MAGEIA8"))) {
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

# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.853631");
  script_version("2021-04-21T07:29:02+0000");
  script_cve_id("CVE-2020-14928", "CVE-2020-16117");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2021-04-21 10:10:24 +0000 (Wed, 21 Apr 2021)");
  script_tag(name:"creation_date", value:"2021-04-16 04:57:27 +0000 (Fri, 16 Apr 2021)");
  script_name("openSUSE: Security Advisory for evolution-data-server (openSUSE-SU-2021:0482-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:0482-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/I3CUVYOHJVMCTZXIKRZXRNXLROM7HCFQ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'evolution-data-server'
  package(s) announced via the openSUSE-SU-2021:0482-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for evolution-data-server fixes the following issues:

  - CVE-2020-16117: Fix crash on malformed server response with minimal
       capabilities (bsc#1174712).

  - CVE-2020-14928: Response injection via STARTTLS in SMTP and POP3
       (bsc#1173910).

  - Fix buffer overrun when parsing base64 data (bsc#1182882).

     This update for evolution-ews fixes the following issue:

  - Fix buffer overrun when parsing base64 data (bsc#1182882).

     This update was imported from the SUSE:SLE-15-SP2:Update update project.");

  script_tag(name:"affected", value:"'evolution-data-server' package(s) on openSUSE Leap 15.2.");

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

if(release == "openSUSELeap15.2") {

  if(!isnull(res = isrpmvuln(pkg:"evolution-data-server", rpm:"evolution-data-server~3.34.4~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evolution-data-server-debuginfo", rpm:"evolution-data-server-debuginfo~3.34.4~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evolution-data-server-debugsource", rpm:"evolution-data-server-debugsource~3.34.4~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evolution-data-server-devel", rpm:"evolution-data-server-devel~3.34.4~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcamel-1_2-62", rpm:"libcamel-1_2-62~3.34.4~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcamel-1_2-62-debuginfo", rpm:"libcamel-1_2-62-debuginfo~3.34.4~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libebackend-1_2-10", rpm:"libebackend-1_2-10~3.34.4~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libebackend-1_2-10-debuginfo", rpm:"libebackend-1_2-10-debuginfo~3.34.4~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libebook-1_2-20", rpm:"libebook-1_2-20~3.34.4~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libebook-1_2-20-debuginfo", rpm:"libebook-1_2-20-debuginfo~3.34.4~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libebook-contacts-1_2-3", rpm:"libebook-contacts-1_2-3~3.34.4~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libebook-contacts-1_2-3-debuginfo", rpm:"libebook-contacts-1_2-3-debuginfo~3.34.4~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libecal-2_0-1", rpm:"libecal-2_0-1~3.34.4~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libecal-2_0-1-debuginfo", rpm:"libecal-2_0-1-debuginfo~3.34.4~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libedata-book-1_2-26", rpm:"libedata-book-1_2-26~3.34.4~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libedata-book-1_2-26-debuginfo", rpm:"libedata-book-1_2-26-debuginfo~3.34.4~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libedata-cal-2_0-1", rpm:"libedata-cal-2_0-1~3.34.4~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libedata-cal-2_0-1-debuginfo", rpm:"libedata-cal-2_0-1-debuginfo~3.34.4~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libedataserver-1_2-24", rpm:"libedataserver-1_2-24~3.34.4~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libedataserver-1_2-24-debuginfo", rpm:"libedataserver-1_2-24-debuginfo~3.34.4~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libedataserverui-1_2-2", rpm:"libedataserverui-1_2-2~3.34.4~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libedataserverui-1_2-2-debuginfo", rpm:"libedataserverui-1_2-2-debuginfo~3.34.4~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-Camel-1_2", rpm:"typelib-1_0-Camel-1_2~3.34.4~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-EBackend-1_2", rpm:"typelib-1_0-EBackend-1_2~3.34.4~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-EBook-1_2", rpm:"typelib-1_0-EBook-1_2~3.34.4~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-EBookContacts-1_2", rpm:"typelib-1_0-EBookContacts-1_2~3.34.4~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-ECal-2_0", rpm:"typelib-1_0-ECal-2_0~3.34.4~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-EDataBook-1_2", rpm:"typelib-1_0-EDataBook-1_2~3.34.4~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-EDataCal-2_0", rpm:"typelib-1_0-EDataCal-2_0~3.34.4~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-EDataServer-1_2", rpm:"typelib-1_0-EDataServer-1_2~3.34.4~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-EDataServerUI-1_2", rpm:"typelib-1_0-EDataServerUI-1_2~3.34.4~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evolution-data-server-lang", rpm:"evolution-data-server-lang~3.34.4~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evolution-ews-lang", rpm:"evolution-ews-lang~3.34.4~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evolution-data-server-32bit", rpm:"evolution-data-server-32bit~3.34.4~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evolution-data-server-32bit-debuginfo", rpm:"evolution-data-server-32bit-debuginfo~3.34.4~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evolution-ews", rpm:"evolution-ews~3.34.4~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evolution-ews-debuginfo", rpm:"evolution-ews-debuginfo~3.34.4~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evolution-ews-debugsource", rpm:"evolution-ews-debugsource~3.34.4~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcamel-1_2-62-32bit", rpm:"libcamel-1_2-62-32bit~3.34.4~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcamel-1_2-62-32bit-debuginfo", rpm:"libcamel-1_2-62-32bit-debuginfo~3.34.4~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libebackend-1_2-10-32bit", rpm:"libebackend-1_2-10-32bit~3.34.4~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libebackend-1_2-10-32bit-debuginfo", rpm:"libebackend-1_2-10-32bit-debuginfo~3.34.4~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libebook-1_2-20-32bit", rpm:"libebook-1_2-20-32bit~3.34.4~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libebook-1_2-20-32bit-debuginfo", rpm:"libebook-1_2-20-32bit-debuginfo~3.34.4~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libebook-contacts-1_2-3-32bit", rpm:"libebook-contacts-1_2-3-32bit~3.34.4~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libebook-contacts-1_2-3-32bit-debuginfo", rpm:"libebook-contacts-1_2-3-32bit-debuginfo~3.34.4~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libecal-2_0-1-32bit", rpm:"libecal-2_0-1-32bit~3.34.4~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libecal-2_0-1-32bit-debuginfo", rpm:"libecal-2_0-1-32bit-debuginfo~3.34.4~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libedata-book-1_2-26-32bit", rpm:"libedata-book-1_2-26-32bit~3.34.4~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libedata-book-1_2-26-32bit-debuginfo", rpm:"libedata-book-1_2-26-32bit-debuginfo~3.34.4~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libedata-cal-2_0-1-32bit", rpm:"libedata-cal-2_0-1-32bit~3.34.4~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libedata-cal-2_0-1-32bit-debuginfo", rpm:"libedata-cal-2_0-1-32bit-debuginfo~3.34.4~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libedataserver-1_2-24-32bit", rpm:"libedataserver-1_2-24-32bit~3.34.4~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libedataserver-1_2-24-32bit-debuginfo", rpm:"libedataserver-1_2-24-32bit-debuginfo~3.34.4~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libedataserverui-1_2-2-32bit", rpm:"libedataserverui-1_2-2-32bit~3.34.4~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libedataserverui-1_2-2-32bit-debuginfo", rpm:"libedataserverui-1_2-2-32bit-debuginfo~3.34.4~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
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
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
  script_oid("1.3.6.1.4.1.25623.1.0.854809");
  script_version("2022-07-22T12:12:01+0000");
  script_cve_id("CVE-2022-1586");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-07-22 12:12:01 +0000 (Fri, 22 Jul 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-26 03:15:00 +0000 (Thu, 26 May 2022)");
  script_tag(name:"creation_date", value:"2022-07-13 01:01:39 +0000 (Wed, 13 Jul 2022)");
  script_name("openSUSE: Security Advisory for pcre (SUSE-SU-2022:2361-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2361-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/JFWEPYJLVFR3H2W7ZTYXJX5DCDXYG6CY");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pcre'
  package(s) announced via the SUSE-SU-2022:2361-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for pcre fixes the following issues:

  - CVE-2022-1586: Fixed unicode property matching issue. (bsc#1199232)");

  script_tag(name:"affected", value:"'pcre' package(s) on openSUSE Leap 15.3, openSUSE Leap 15.4.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"libpcre1", rpm:"libpcre1~8.45~150000.20.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre1-debuginfo", rpm:"libpcre1-debuginfo~8.45~150000.20.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre16-0", rpm:"libpcre16-0~8.45~150000.20.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre16-0-debuginfo", rpm:"libpcre16-0-debuginfo~8.45~150000.20.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcrecpp0", rpm:"libpcrecpp0~8.45~150000.20.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcrecpp0-debuginfo", rpm:"libpcrecpp0-debuginfo~8.45~150000.20.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcreposix0", rpm:"libpcreposix0~8.45~150000.20.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcreposix0-debuginfo", rpm:"libpcreposix0-debuginfo~8.45~150000.20.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcre-debugsource", rpm:"pcre-debugsource~8.45~150000.20.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcre-devel", rpm:"pcre-devel~8.45~150000.20.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcre-devel-static", rpm:"pcre-devel-static~8.45~150000.20.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcre-tools", rpm:"pcre-tools~8.45~150000.20.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcre-tools-debuginfo", rpm:"pcre-tools-debuginfo~8.45~150000.20.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre1-32bit", rpm:"libpcre1-32bit~8.45~150000.20.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre1-32bit-debuginfo", rpm:"libpcre1-32bit-debuginfo~8.45~150000.20.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre16-0-32bit", rpm:"libpcre16-0-32bit~8.45~150000.20.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre16-0-32bit-debuginfo", rpm:"libpcre16-0-32bit-debuginfo~8.45~150000.20.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcrecpp0-32bit", rpm:"libpcrecpp0-32bit~8.45~150000.20.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcrecpp0-32bit-debuginfo", rpm:"libpcrecpp0-32bit-debuginfo~8.45~150000.20.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcreposix0-32bit", rpm:"libpcreposix0-32bit~8.45~150000.20.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcreposix0-32bit-debuginfo", rpm:"libpcreposix0-32bit-debuginfo~8.45~150000.20.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcre-doc", rpm:"pcre-doc~8.45~150000.20.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"libpcre1", rpm:"libpcre1~8.45~150000.20.13.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre1-debuginfo", rpm:"libpcre1-debuginfo~8.45~150000.20.13.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre16-0", rpm:"libpcre16-0~8.45~150000.20.13.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre16-0-debuginfo", rpm:"libpcre16-0-debuginfo~8.45~150000.20.13.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcrecpp0", rpm:"libpcrecpp0~8.45~150000.20.13.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcrecpp0-debuginfo", rpm:"libpcrecpp0-debuginfo~8.45~150000.20.13.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcreposix0", rpm:"libpcreposix0~8.45~150000.20.13.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcreposix0-debuginfo", rpm:"libpcreposix0-debuginfo~8.45~150000.20.13.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcre-debugsource", rpm:"pcre-debugsource~8.45~150000.20.13.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcre-devel", rpm:"pcre-devel~8.45~150000.20.13.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcre-devel-static", rpm:"pcre-devel-static~8.45~150000.20.13.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcre-tools", rpm:"pcre-tools~8.45~150000.20.13.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcre-tools-debuginfo", rpm:"pcre-tools-debuginfo~8.45~150000.20.13.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre1-32bit", rpm:"libpcre1-32bit~8.45~150000.20.13.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre1-32bit-debuginfo", rpm:"libpcre1-32bit-debuginfo~8.45~150000.20.13.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre16-0-32bit", rpm:"libpcre16-0-32bit~8.45~150000.20.13.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre16-0-32bit-debuginfo", rpm:"libpcre16-0-32bit-debuginfo~8.45~150000.20.13.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcrecpp0-32bit", rpm:"libpcrecpp0-32bit~8.45~150000.20.13.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcrecpp0-32bit-debuginfo", rpm:"libpcrecpp0-32bit-debuginfo~8.45~150000.20.13.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcreposix0-32bit", rpm:"libpcreposix0-32bit~8.45~150000.20.13.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcreposix0-32bit-debuginfo", rpm:"libpcreposix0-32bit-debuginfo~8.45~150000.20.13.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcre-doc", rpm:"pcre-doc~8.45~150000.20.13.1", rls:"openSUSELeap15.3"))) {
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
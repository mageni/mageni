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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.4253.1");
  script_cve_id("CVE-2011-5325", "CVE-2014-9645", "CVE-2015-9261", "CVE-2016-2147", "CVE-2016-2148", "CVE-2016-6301", "CVE-2017-15873", "CVE-2017-15874", "CVE-2017-16544", "CVE-2018-1000500", "CVE-2018-1000517", "CVE-2018-20679", "CVE-2019-5747", "CVE-2021-28831", "CVE-2021-42373", "CVE-2021-42374", "CVE-2021-42375", "CVE-2021-42376", "CVE-2021-42377", "CVE-2021-42378", "CVE-2021-42379", "CVE-2021-42380", "CVE-2021-42381", "CVE-2021-42382", "CVE-2021-42383", "CVE-2021-42384", "CVE-2021-42385", "CVE-2021-42386");
  script_tag(name:"creation_date", value:"2022-11-29 04:18:38 +0000 (Tue, 29 Nov 2022)");
  script_version("2022-11-29T10:12:26+0000");
  script_tag(name:"last_modification", value:"2022-11-29 10:12:26 +0000 (Tue, 29 Nov 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-17 19:41:00 +0000 (Wed, 17 Nov 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:4253-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2|SLES12\.0SP3|SLES12\.0SP4|SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:4253-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20224253-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'busybox' package(s) announced via the SUSE-SU-2022:4253-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for busybox fixes the following issues:

CVE-2014-9645: Fixed loading of unwanted modules with / (bsc#914660).

CVE-2017-16544: Fixed insufficient sanitization of filenames when
 autocompleting (bsc#1069412).

CVE-2015-9261: Fixed huft_build misuses a pointer, causing segfaults
 (bsc#1102912).

CVE-2016-2147: Fixed out of bounds write (heap) due to integer underflow
 in udhcpc (bsc#970663).

CVE-2016-2148: Fixed heap-based buffer overflow in OPTION_6RD parsing
 (bsc#970662).

CVE-2016-6301: Fixed NTP server denial of service flaw (bsc#991940).

CVE-2017-15873: Fixed integer overflow in get_next_block function in
 archival/libarchive/decompress_bunzip2.c (bsc#1064976).

CVE-2017-15874: Fixed integer overflow in
 archival/libarchive/decompress_unlzma (bsc#1064978).

CVE-2019-5747: Fixed out of bounds read in udhcp components
 (bsc#1121428).

CVE-2021-42373, CVE-2021-42374, CVE-2021-42375, CVE-2021-42376,
 CVE-2021-42377, CVE-2021-42378, CVE-2021-42379, CVE-2021-42380,
 CVE-2021-42381, CVE-2021-42382, CVE-2021-42383, CVE-2021-42384,
 CVE-2021-42385, CVE-2021-42386: v1.34.0 bugfixes (bsc#1192869).

CVE-2021-28831: Fixed invalid free or segmentation fault via malformed
 gzip data (bsc#1184522).

CVE-2018-20679: Fixed out of bounds read in udhcp (bsc#1121426).

CVE-2018-1000517: Fixed heap-based buffer overflow in the
 retrieve_file_data() (bsc#1099260).

CVE-2011-5325: Fixed tar directory traversal (bsc#951562).

CVE-2018-1000500: Fixed missing SSL certificate validation in wget
 (bsc#1099263).

Update to 1.35.0
 - awk: fix printf %%, fix read beyond end of buffer
 - chrt: silence analyzer warning
 - libarchive: remove duplicate forward declaration
 - mount: 'mount -o rw ....' should not fall back to RO mount
 - ps: fix -o pid=PID,args interpreting entire 'PID,args' as header
 - tar: prevent malicious archives with long name sizes causing OOM
 - udhcpc6: fix udhcp_find_option to actually find DHCP6 options
 - xxd: fix -p -r
 - support for new optoins added to basename, cpio, date, find, mktemp,
 wget and others

Enable fdisk (jsc#CAR-16)

Update to 1.34.1:
 * build system: use SOURCE_DATE_EPOCH for timestamp if available
 * many bug fixes and new features
 * touch: make FEATURE_TOUCH_NODEREF unconditional

update to 1.33.1:
 * httpd: fix sendfile
 * ash: fix HISTFILE corruptio
 * ash: fix unset variable pattern expansion
 * traceroute: fix option parsing
 * gunzip: fix for archive corruption

Update to version 1.33.0
 - many bug fixes and new features

Update to version 1.32.1
 - fixes a case where in ash, 'wait' never finishes.

prepare usrmerge (bsc#1029961)

Enable testsuite and package it for later rerun (for QA, jsc#CAR-15)

Update to version 1.31.1:
 + Bug fix release. 1.30.1 has fixes for dc, ash (PS1 expansion fix),
 hush, dpkg-deb, telnet and wget.

Changes from version 1.31.0:
 + many bugfixes and new features.

Add busybox-no-stime.patch: stime() has ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'busybox' package(s) on SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP 12-SP4, SUSE OpenStack Cloud 9, SUSE OpenStack Cloud Crowbar 9.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"busybox", rpm:"busybox~1.35.0~4.3.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"busybox", rpm:"busybox~1.35.0~4.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"busybox", rpm:"busybox~1.35.0~4.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"busybox", rpm:"busybox~1.35.0~4.3.1", rls:"SLES12.0SP5"))) {
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

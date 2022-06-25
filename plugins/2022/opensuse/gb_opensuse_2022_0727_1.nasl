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
  script_oid("1.3.6.1.4.1.25623.1.0.854540");
  script_version("2022-03-15T08:14:31+0000");
  script_cve_id("CVE-2021-3995", "CVE-2021-3996");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-03-15 11:02:07 +0000 (Tue, 15 Mar 2022)");
  script_tag(name:"creation_date", value:"2022-03-05 02:02:11 +0000 (Sat, 05 Mar 2022)");
  script_name("openSUSE: Security Advisory for libeconf, (openSUSE-SU-2022:0727-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2022:0727-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/GUBUSLRBG42MLRL65HHMLIWQIKS3SKKP");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libeconf, '
  package(s) announced via the openSUSE-SU-2022:0727-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This security update for libeconf, shadow and util-linux fix the following
     issues:
  libeconf:

  - Add libeconf to SLE-Module-Basesystem_15-SP3 because needed by
       'util-linux' and 'shadow' to fix autoyast handling of security related
       parameters (bsc#1192954, jsc#SLE-23384, jsc#SLE-23402)
  Issues fixed in libeconf:

  - Reading numbers with different bases (e.g. oktal) (bsc#1193632) (#157)

  - Fixed different issues while writing string values to file.

  - Writing comments to file too.

  - Fixed crash while merging values.

  - Added econftool cat option (#146)

  - new API call: econf_readDirsHistory (showing ALL locations)

  - new API call: econf_getPath (absolute path of the configuration file)

  - Man pages libeconf.3 and econftool.8.

  - Handling multiline strings.

  - Added libeconf_ext which returns more information like line_nr,
       comments, path of the configuration file, ...

  - Econftool, an command line interface for handling configuration files.

  - Generating HTML API documentation with doxygen.

  - Improving error handling and semantic file check.

  - Joining entries with the same key to one single entry if env variable
       ECONF_JOIN_SAME_ENTRIES has been set.
  shadow:

  - The legacy code does not support /etc/login.defs.d used by YaST. Enable
       libeconf to read it (bsc#1192954, jsc#SLE-23384, jsc#SLE-23402)
  util-linux:

  - The legacy code does not support /etc/login.defs.d used by YaST. Enable
       libeconf to read it (bsc#1192954, jsc#SLE-23384, jsc#SLE-23402)

  - Allow use of larger values for start sector to prevent `blockdev

  - -report` aborting (bsc#1188507)

  - Fixed `blockdev --report` using non-space characters as a field
       separator (bsc#1188507)

  - CVE-2021-3995: Fixed unauthorized unmount in util-linux's libmount.
       (bsc#1194976)

  - CVE-2021-3996: Fixed unauthorized unmount in util-linux's libmount.
       (bsc#1194976)");

  script_tag(name:"affected", value:"'libeconf, ' package(s) on openSUSE Leap 15.3.");

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

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"libblkid-devel", rpm:"libblkid-devel~2.36.2~150300.4.14.3", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblkid-devel-static", rpm:"libblkid-devel-static~2.36.2~150300.4.14.3", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblkid1", rpm:"libblkid1~2.36.2~150300.4.14.3", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblkid1-debuginfo", rpm:"libblkid1-debuginfo~2.36.2~150300.4.14.3", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libeconf-debugsource", rpm:"libeconf-debugsource~0.4.4+git20220104.962774f~150300.3.6.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libeconf-devel", rpm:"libeconf-devel~0.4.4+git20220104.962774f~150300.3.6.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libeconf0", rpm:"libeconf0~0.4.4+git20220104.962774f~150300.3.6.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libeconf0-debuginfo", rpm:"libeconf0-debuginfo~0.4.4+git20220104.962774f~150300.3.6.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfdisk-devel", rpm:"libfdisk-devel~2.36.2~150300.4.14.3", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfdisk-devel-static", rpm:"libfdisk-devel-static~2.36.2~150300.4.14.3", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfdisk1", rpm:"libfdisk1~2.36.2~150300.4.14.3", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfdisk1-debuginfo", rpm:"libfdisk1-debuginfo~2.36.2~150300.4.14.3", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmount-devel", rpm:"libmount-devel~2.36.2~150300.4.14.3", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmount-devel-static", rpm:"libmount-devel-static~2.36.2~150300.4.14.3", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmount1", rpm:"libmount1~2.36.2~150300.4.14.3", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmount1-debuginfo", rpm:"libmount1-debuginfo~2.36.2~150300.4.14.3", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmartcols-devel", rpm:"libsmartcols-devel~2.36.2~150300.4.14.3", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmartcols-devel-static", rpm:"libsmartcols-devel-static~2.36.2~150300.4.14.3", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmartcols1", rpm:"libsmartcols1~2.36.2~150300.4.14.3", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmartcols1-debuginfo", rpm:"libsmartcols1-debuginfo~2.36.2~150300.4.14.3", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libuuid-devel", rpm:"libuuid-devel~2.36.2~150300.4.14.3", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libuuid-devel-static", rpm:"libuuid-devel-static~2.36.2~150300.4.14.3", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libuuid1", rpm:"libuuid1~2.36.2~150300.4.14.3", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libuuid1-debuginfo", rpm:"libuuid1-debuginfo~2.36.2~150300.4.14.3", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-libmount", rpm:"python3-libmount~2.36.2~150300.4.14.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-libmount-debuginfo", rpm:"python3-libmount-debuginfo~2.36.2~150300.4.14.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-libmount-debugsource", rpm:"python3-libmount-debugsource~2.36.2~150300.4.14.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"shadow", rpm:"shadow~4.8.1~150300.4.3.8", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"shadow-debuginfo", rpm:"shadow-debuginfo~4.8.1~150300.4.3.8", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"shadow-debugsource", rpm:"shadow-debugsource~4.8.1~150300.4.3.8", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"util-linux", rpm:"util-linux~2.36.2~150300.4.14.3", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"util-linux-debuginfo", rpm:"util-linux-debuginfo~2.36.2~150300.4.14.3", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"util-linux-debugsource", rpm:"util-linux-debugsource~2.36.2~150300.4.14.3", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"util-linux-systemd", rpm:"util-linux-systemd~2.36.2~150300.4.14.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"util-linux-systemd-debuginfo", rpm:"util-linux-systemd-debuginfo~2.36.2~150300.4.14.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"util-linux-systemd-debugsource", rpm:"util-linux-systemd-debugsource~2.36.2~150300.4.14.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uuidd", rpm:"uuidd~2.36.2~150300.4.14.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uuidd-debuginfo", rpm:"uuidd-debuginfo~2.36.2~150300.4.14.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblkid-devel-32bit", rpm:"libblkid-devel-32bit~2.36.2~150300.4.14.3", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblkid1-32bit", rpm:"libblkid1-32bit~2.36.2~150300.4.14.3", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblkid1-32bit-debuginfo", rpm:"libblkid1-32bit-debuginfo~2.36.2~150300.4.14.3", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libeconf0-32bit", rpm:"libeconf0-32bit~0.4.4+git20220104.962774f~150300.3.6.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libeconf0-32bit-debuginfo", rpm:"libeconf0-32bit-debuginfo~0.4.4+git20220104.962774f~150300.3.6.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfdisk-devel-32bit", rpm:"libfdisk-devel-32bit~2.36.2~150300.4.14.3", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfdisk1-32bit", rpm:"libfdisk1-32bit~2.36.2~150300.4.14.3", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfdisk1-32bit-debuginfo", rpm:"libfdisk1-32bit-debuginfo~2.36.2~150300.4.14.3", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmount-devel-32bit", rpm:"libmount-devel-32bit~2.36.2~150300.4.14.3", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmount1-32bit", rpm:"libmount1-32bit~2.36.2~150300.4.14.3", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmount1-32bit-debuginfo", rpm:"libmount1-32bit-debuginfo~2.36.2~150300.4.14.3", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmartcols-devel-32bit", rpm:"libsmartcols-devel-32bit~2.36.2~150300.4.14.3", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmartcols1-32bit", rpm:"libsmartcols1-32bit~2.36.2~150300.4.14.3", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmartcols1-32bit-debuginfo", rpm:"libsmartcols1-32bit-debuginfo~2.36.2~150300.4.14.3", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libuuid-devel-32bit", rpm:"libuuid-devel-32bit~2.36.2~150300.4.14.3", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libuuid1-32bit", rpm:"libuuid1-32bit~2.36.2~150300.4.14.3", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libuuid1-32bit-debuginfo", rpm:"libuuid1-32bit-debuginfo~2.36.2~150300.4.14.3", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"login_defs", rpm:"login_defs~4.8.1~150300.4.3.8", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"util-linux-lang", rpm:"util-linux-lang~2.36.2~150300.4.14.3", rls:"openSUSELeap15.3"))) {
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
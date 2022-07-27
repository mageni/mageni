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
  script_oid("1.3.6.1.4.1.25623.1.0.853801");
  script_version("2021-05-10T06:49:03+0000");
  script_cve_id("CVE-2021-21309", "CVE-2021-29477", "CVE-2021-29478");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-05-10 10:15:03 +0000 (Mon, 10 May 2021)");
  script_tag(name:"creation_date", value:"2021-05-08 03:01:19 +0000 (Sat, 08 May 2021)");
  script_name("openSUSE: Security Advisory for redis (openSUSE-SU-2021:0682-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:0682-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/Z32YY6DUIFNGIYRC6JPVBZ2WTPYN5SOY");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'redis'
  package(s) announced via the openSUSE-SU-2021:0682-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for redis fixes the following issues:

     redis 6.0.13

  * CVE-2021-29477: Integer overflow in STRALGO LCS command (boo#1185729)

  * CVE-2021-29478: Integer overflow in COPY command for large intsets
       (boo#1185730)

  * Cluster: Skip unnecessary check which may prevent failure detection

  * Fix performance regression in BRPOP on Redis 6.0

  * Fix edge-case when a module client is unblocked

     redis 6.0.12:

  * Fix compilation error on non-glibc systems if jemalloc is not used

     redis 6.0.11:

  * CVE-2021-21309: Avoid 32-bit overflows when proto-max-bulk-len is set
       high (boo#1182657)

  * Fix handling of threaded IO and CLIENT PAUSE (failover), could lead to
       data loss or a crash

  * Fix the selection of a random element from large hash tables

  * Fix broken protocol in client tracking tracking-redir-broken message

  * XINFO able to access expired keys on a replica

  * Fix broken protocol in redis-benchmark when used with -a or --dbnum

  * Avoid assertions (on older kernels) when testing arm64 CoW bug

  * CONFIG REWRITE should honor umask settings

  * Fix firstkey, lastkey, step in COMMAND command for some commands

  * RM_ZsetRem: Delete key if empty, the bug could leave empty zset keys

     redis 6.0.10:

     Command behavior changes:

  * SWAPDB invalidates WATCHed keys (#8239)

  * SORT command behaves differently when used on a writable replica (#8283)

  * EXISTS should not alter LRU (#8016) In Redis 5.0 and 6.0 it would have
       touched the LRU/LFU of the key.

  * OBJECT should not reveal logically expired keys (#8016) Will now behave
       the same TYPE or any other non-DEBUG command.

  * GEORADIUS[BYMEMBER] can fail with -OOM if Redis is over the memory limit
       (#8107)

     Other behavior changes:

  * Sentinel: Fix missing updates to the config file after SENTINEL SET
       command (#8229)

  * CONFIG REWRITE is atomic and safer, but requires write access to the
       config file&#x27 s folder (#7824, #8051) This change was already present in
       6.0.9, but was missing from the release notes.

     Bug fixes with compatibility implications (bugs introduced in Redis 6.0):

  * Fix RDB CRC64 checksum on big-endian systems (#8270) If you&#x27 re using
       big-endian please consider the compatibility implications with RESTORE,
       replication and persistence.

  * Fix wrong order of key/value in Lua&#x27 s map response (#8266) If your
       scripts use redis.setresp() or return a map (new in Redis 6.0), please
       consider the implications.

      ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'redis' package(s) on openSUSE Leap 15.2.");

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

  if(!isnull(res = isrpmvuln(pkg:"redis", rpm:"redis~6.0.13~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"redis-debuginfo", rpm:"redis-debuginfo~6.0.13~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"redis-debugsource", rpm:"redis-debugsource~6.0.13~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
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
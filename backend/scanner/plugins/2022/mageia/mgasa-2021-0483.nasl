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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0483");
  script_cve_id("CVE-2021-32626", "CVE-2021-32627", "CVE-2021-32628", "CVE-2021-32672", "CVE-2021-32675", "CVE-2021-32687", "CVE-2021-32762", "CVE-2021-41099");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-02-01T09:43:59+0000");
  script_tag(name:"last_modification", value:"2022-02-01 09:43:59 +0000 (Tue, 01 Feb 2022)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-13 16:04:00 +0000 (Wed, 13 Oct 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0483)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0483");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0483.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29552");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/VL5KXFN3ATM7IIM7Q4O4PWTSRGZ5744Z/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/HTYQ5ZF37HNGTZWVNJD3VXP7I6MEEF42/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'redis' package(s) announced via the MGASA-2021-0483 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2021-32626: Specially crafted Lua scripts executing in Redis can cause
the heap-based Lua stack to be overflowed, due to incomplete checks for this
condition. This can result with heap corruption and potentially remote code
execution.
CVE-2021-32627: An integer overflow bug in Redis 5.0 or newer can be exploited
to corrupt the heap and potentially result with remote code execution.
CVE-2021-32628: An integer overflow bug in the ziplist data structure used by
all versions of Redis can be exploited to corrupt the heap and potentially
result with remote code execution.
CVE-2021-32672: When using the Redis Lua Debugger, users can send malformed
requests that cause the debugger's protocol parser to read data beyond the
actual buffer.
CVE-2021-32675: When parsing an incoming Redis Standard Protocol (RESP)
request, Redis allocates memory according to user-specified values which
determine the number of elements (in the multi-bulk header) and size of each
element (in the bulk header).
CVE-2021-32687: An integer overflow bug affecting all versions of Redis can
be exploited to corrupt the heap and potentially be used to leak arbitrary
contents of the heap or trigger remote code execution.
CVE-2021-32762: The redis-cli command line tool and redis-sentinel service
may be vulnerable to integer overflow when parsing specially crafted large
multi-bulk network replies.
CVE-2021-41099: An integer overflow bug in the underlying string library can
be used to corrupt the heap and potentially result with denial of service or
remote code execution.");

  script_tag(name:"affected", value:"'redis' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"redis", rpm:"redis~6.0.16~1.mga8", rls:"MAGEIA8"))) {
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

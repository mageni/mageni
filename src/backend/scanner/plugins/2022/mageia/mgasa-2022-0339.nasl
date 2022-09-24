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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0339");
  script_cve_id("CVE-2022-24735", "CVE-2022-24736");
  script_tag(name:"creation_date", value:"2022-09-22 04:40:55 +0000 (Thu, 22 Sep 2022)");
  script_version("2022-09-22T10:44:54+0000");
  script_tag(name:"last_modification", value:"2022-09-22 10:44:54 +0000 (Thu, 22 Sep 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-09 17:15:00 +0000 (Mon, 09 May 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0339)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0339");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0339.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30393");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/VPYKSG7LKUJGVM2P72EHXKVRVRWHLORX/");
  script_xref(name:"URL", value:"https://github.com/redis/redis/security/advisories/GHSA-647m-2wmq-qmvq");
  script_xref(name:"URL", value:"https://github.com/redis/redis/security/advisories/GHSA-3qpw-7686-5984");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/NERGELOQ43TXPK5SCGTMYFI4KDXITL74/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'redis' package(s) announced via the MGASA-2022-0339 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Redis is an in-memory database that persists on disk. By exploiting
weaknesses in the Lua script execution environment, an attacker with
access to Redis prior to version 7.0.0 or 6.2.7 can inject Lua code that
will execute with the (potentially higher) privileges of another Redis
user. The Lua script execution environment in Redis provides some measures
that prevent a script from creating side effects that persist and can
affect the execution of the same, or different script, at a later time.
Several weaknesses of these measures have been publicly known for a long
time, but they had no security impact as the Redis security model did not
endorse the concept of users or privileges. With the introduction of ACLs
in Redis 6.0, these weaknesses can be exploited by a less privileged
users to inject Lua code that will execute at a later time, when a
privileged user executes a Lua script. The problem is fixed in Redis
versions 7.0.0 and 6.2.7. An additional workaround to mitigate this
problem without patching the redis-server executable, if Lua scripting is
not being used, is to block access to `SCRIPT LOAD` and `EVAL` commands
using ACL rules. (CVE-2022-24735)

Redis is an in-memory database that persists on disk. Prior to versions
6.2.7 and 7.0.0, an attacker attempting to load a specially crafted Lua
script can cause NULL pointer dereference which will result with a crash
of the redis-server process. The problem is fixed in Redis versions 7.0.0
and 6.2.7. An additional workaround to mitigate this problem without
patching the redis-server executable, if Lua scripting is not being used,
is to block access to `SCRIPT LOAD` and `EVAL` commands using ACL rules.
(CVE-2022-24736)");

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

  if(!isnull(res = isrpmvuln(pkg:"redis", rpm:"redis~6.0.16~1.1.mga8", rls:"MAGEIA8"))) {
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

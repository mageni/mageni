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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0205");
  script_cve_id("CVE-2014-0060", "CVE-2014-0061", "CVE-2014-0062", "CVE-2014-0063", "CVE-2014-0064", "CVE-2014-0065", "CVE-2014-0066", "CVE-2014-0067");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-12-16 02:29:00 +0000 (Sat, 16 Dec 2017)");

  script_name("Mageia: Security Advisory (MGASA-2014-0205)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0205");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0205.html");
  script_xref(name:"URL", value:"http://article.gmane.org/gmane.comp.db.postgresql.announce/2371");
  script_xref(name:"URL", value:"http://article.gmane.org/gmane.comp.db.postgresql.announce/2386");
  script_xref(name:"URL", value:"http://www.mandriva.com/en/support/security/advisories/mbs1/MDVSA-2014:047/");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=13241");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=12841");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql9.0, postgresql9.1, postgresql9.2, postgresql9.3' package(s) announced via the MGASA-2014-0205 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated postgresql packages fix security vulnerabilities:

Granting a role without ADMIN OPTION is supposed to prevent the
grantee from adding or removing members from the granted role, but
this restriction was easily bypassed by doing SET ROLE first. The
security impact is mostly that a role member can revoke the access
of others, contrary to the wishes of his grantor. Unapproved role
member additions are a lesser concern, since an uncooperative role
member could provide most of his rights to others anyway by creating
views or SECURITY DEFINER functions (CVE-2014-0060).

The primary role of PL validator functions is to be called implicitly
during CREATE FUNCTION, but they are also normal SQL functions
that a user can call explicitly. Calling a validator on a function
actually written in some other language was not checked for and could
be exploited for privilege-escalation purposes. The fix involves
adding a call to a privilege-checking function in each validator
function. Non-core procedural languages will also need to make this
change to their own validator functions, if any (CVE-2014-0061).

If the name lookups come to different conclusions due to concurrent
activity, we might perform some parts of the DDL on a different
table than other parts. At least in the case of CREATE INDEX, this
can be used to cause the permissions checks to be performed against
a different table than the index creation, allowing for a privilege
escalation attack (CVE-2014-0062).

The MAXDATELEN constant was too small for the longest possible value of
type interval, allowing a buffer overrun in interval_out(). Although
the datetime input functions were more careful about avoiding buffer
overrun, the limit was short enough to cause them to reject some valid
inputs, such as input containing a very long timezone name. The ecpg
library contained these vulnerabilities along with some of its own
(CVE-2014-0063).

Several functions, mostly type input functions, calculated an
allocation size without checking for overflow. If overflow did
occur, a too-small buffer would be allocated and then written past
(CVE-2014-0064).

Use strlcpy() and related functions to provide a clear guarantee
that fixed-size buffers are not overrun. Unlike the preceding items,
it is unclear whether these cases really represent live issues,
since in most cases there appear to be previous constraints on the
size of the input string. Nonetheless it seems prudent to silence
all Coverity warnings of this type (CVE-2014-0065).

There are relatively few scenarios in which crypt() could return NULL,
but contrib/chkpass would crash if it did. One practical case in which
this could be an issue is if libc is configured to refuse to execute
unapproved hashing algorithms (e.g., FIPS mode) (CVE-2014-0066).

Since the temporary server started by make check uses trust
authentication, another user on the same machine could connect to it
as ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'postgresql9.0, postgresql9.1, postgresql9.2, postgresql9.3' package(s) on Mageia 4.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"lib64ecpg9.0_6", rpm:"lib64ecpg9.0_6~9.0.17~2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ecpg9.1_6", rpm:"lib64ecpg9.1_6~9.1.13~2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ecpg9.2_6", rpm:"lib64ecpg9.2_6~9.2.8~2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ecpg9.3_6", rpm:"lib64ecpg9.3_6~9.3.4~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pq9.0_5.3", rpm:"lib64pq9.0_5.3~9.0.17~2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pq9.1_5.4", rpm:"lib64pq9.1_5.4~9.1.13~2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pq9.2_5.5", rpm:"lib64pq9.2_5.5~9.2.8~2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pq9.3_5", rpm:"lib64pq9.3_5~9.3.4~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libecpg9.0_6", rpm:"libecpg9.0_6~9.0.17~2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libecpg9.1_6", rpm:"libecpg9.1_6~9.1.13~2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libecpg9.2_6", rpm:"libecpg9.2_6~9.2.8~2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libecpg9.3_6", rpm:"libecpg9.3_6~9.3.4~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq9.0_5.3", rpm:"libpq9.0_5.3~9.0.17~2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq9.1_5.4", rpm:"libpq9.1_5.4~9.1.13~2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq9.2_5.5", rpm:"libpq9.2_5.5~9.2.8~2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq9.3_5", rpm:"libpq9.3_5~9.3.4~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.0", rpm:"postgresql9.0~9.0.17~2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.0-contrib", rpm:"postgresql9.0-contrib~9.0.17~2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.0-devel", rpm:"postgresql9.0-devel~9.0.17~2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.0-docs", rpm:"postgresql9.0-docs~9.0.17~2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.0-pl", rpm:"postgresql9.0-pl~9.0.17~2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.0-plperl", rpm:"postgresql9.0-plperl~9.0.17~2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.0-plpgsql", rpm:"postgresql9.0-plpgsql~9.0.17~2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.0-plpython", rpm:"postgresql9.0-plpython~9.0.17~2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.0-pltcl", rpm:"postgresql9.0-pltcl~9.0.17~2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.0-server", rpm:"postgresql9.0-server~9.0.17~2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.1", rpm:"postgresql9.1~9.1.13~2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.1-contrib", rpm:"postgresql9.1-contrib~9.1.13~2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.1-devel", rpm:"postgresql9.1-devel~9.1.13~2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.1-docs", rpm:"postgresql9.1-docs~9.1.13~2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.1-pl", rpm:"postgresql9.1-pl~9.1.13~2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.1-plperl", rpm:"postgresql9.1-plperl~9.1.13~2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.1-plpgsql", rpm:"postgresql9.1-plpgsql~9.1.13~2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.1-plpython", rpm:"postgresql9.1-plpython~9.1.13~2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.1-pltcl", rpm:"postgresql9.1-pltcl~9.1.13~2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.1-server", rpm:"postgresql9.1-server~9.1.13~2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.2", rpm:"postgresql9.2~9.2.8~2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.2-contrib", rpm:"postgresql9.2-contrib~9.2.8~2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.2-devel", rpm:"postgresql9.2-devel~9.2.8~2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.2-docs", rpm:"postgresql9.2-docs~9.2.8~2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.2-pl", rpm:"postgresql9.2-pl~9.2.8~2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.2-plperl", rpm:"postgresql9.2-plperl~9.2.8~2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.2-plpgsql", rpm:"postgresql9.2-plpgsql~9.2.8~2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.2-plpython", rpm:"postgresql9.2-plpython~9.2.8~2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.2-pltcl", rpm:"postgresql9.2-pltcl~9.2.8~2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.2-server", rpm:"postgresql9.2-server~9.2.8~2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.3", rpm:"postgresql9.3~9.3.4~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.3-contrib", rpm:"postgresql9.3-contrib~9.3.4~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.3-devel", rpm:"postgresql9.3-devel~9.3.4~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.3-docs", rpm:"postgresql9.3-docs~9.3.4~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.3-pl", rpm:"postgresql9.3-pl~9.3.4~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.3-plperl", rpm:"postgresql9.3-plperl~9.3.4~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.3-plpgsql", rpm:"postgresql9.3-plpgsql~9.3.4~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.3-plpython", rpm:"postgresql9.3-plpython~9.3.4~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.3-pltcl", rpm:"postgresql9.3-pltcl~9.3.4~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.3-server", rpm:"postgresql9.3-server~9.3.4~1.mga4", rls:"MAGEIA4"))) {
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

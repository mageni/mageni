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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0009");
  script_cve_id("CVE-2018-10851", "CVE-2018-14626", "CVE-2018-14644", "CVE-2018-16855");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:33:00 +0000 (Wed, 09 Oct 2019)");

  script_name("Mageia: Security Advisory (MGASA-2019-0009)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0009");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0009.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=23815");
  script_xref(name:"URL", value:"https://doc.powerdns.com/recursor/security-advisories/powerdns-advisory-2018-04.html");
  script_xref(name:"URL", value:"https://doc.powerdns.com/recursor/security-advisories/powerdns-advisory-2018-06.html");
  script_xref(name:"URL", value:"https://docs.powerdns.com/recursor/security-advisories/powerdns-advisory-2018-07.html");
  script_xref(name:"URL", value:"https://docs.powerdns.com/recursor/security-advisories/powerdns-advisory-2018-09.html");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/U5BJ2CLRPCLSDHOH3VAABZZP4GVKGLL5/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pdns-recursor' package(s) announced via the MGASA-2019-0009 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability was in found in PowerDNS Recursor. The issue is a memory
leak occurring while parsing some malformed records, due to the fact
that some memory is allocated parsing a record and is not always
properly released if the record is not valid. It allows a malicious auth
server to cause a denial of service by sending specially crafted records
in response to a legitimate query by an authorized user (CVE-2018-10851).

An issue has been found in PowerDNS Recursor allowing a remote user to
craft a DNS query that will cause an answer without DNSSEC records to be
inserted into the packet cache and be returned to clients asking for
DNSSEC records, thus hiding the presence of DNSSEC signatures for a
specific qname and qtype. For a DNSSEC-signed domain, this means that
clients performing DNSSEC validation by themselves might consider the
answer to be bogus until it expires from the packet cache, leading to a
denial of service (CVE-2018-14626).

An issue has been found in PowerDNS Recursor from 4.0.0 up to and
including 4.1.4. A remote attacker sending a DNS query for a meta-type
like OPT can lead to a zone being wrongly cached as failing DNSSEC
validation. It only arises if the parent zone is signed, and all the
authoritative servers for that parent zone answer with FORMERR to a
query for at least one of the meta-types. As a result, subsequent
queries from clients requesting DNSSEC validation will be answered with
a ServFail (CVE-2018-14644).

An issue has been found in PowerDNS Recursor where a remote attacker
sending a DNS query can trigger an out-of-bounds memory read while
computing the hash of the query for a packet cache lookup, possibly
leading to a crash (CVE-2018-16855).");

  script_tag(name:"affected", value:"'pdns-recursor' package(s) on Mageia 6.");

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

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"pdns-recursor", rpm:"pdns-recursor~4.1.8~1.mga6", rls:"MAGEIA6"))) {
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

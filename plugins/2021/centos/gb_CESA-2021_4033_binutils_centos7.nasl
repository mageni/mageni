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
  script_oid("1.3.6.1.4.1.25623.1.0.883385");
  script_version("2021-11-29T04:48:32+0000");
  script_cve_id("CVE-2021-42574");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-11-29 10:38:15 +0000 (Mon, 29 Nov 2021)");
  script_tag(name:"creation_date", value:"2021-11-18 02:01:49 +0000 (Thu, 18 Nov 2021)");
  script_name("CentOS: Security Advisory for binutils (CESA-2021:4033)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"Advisory-ID", value:"CESA-2021:4033");
  script_xref(name:"URL", value:"https://lists.centos.org/pipermail/centos-announce/2021-November/048395.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'binutils'
  package(s) announced via the CESA-2021:4033 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The binutils packages provide a collection of binary utilities for the
manipulation of object code in various object file formats. It includes the
ar, as, gprof, ld, nm, objcopy, objdump, ranlib, readelf, size, strings,
strip, and addr2line utilities.

Security Fix(es):

  * Developer environment: Unicode's bidirectional (BiDi) override characters
can cause trojan source attacks (CVE-2021-42574)

The following changes were introduced in binutils in order to facilitate
detection of BiDi Unicode characters:

Tools which display names or strings (readelf, strings, nm, objdump) have a
new command line option --unicode / -U which controls how Unicode
characters are handled.

Using '--unicode=default' will treat them as normal for the tool. This is
the default behaviour when --unicode option is not used.
Using '--unicode=locale' will display them according to the current locale.
Using '--unicode=hex' will display them as hex byte values.
Using '--unicode=escape' will display them as Unicode escape sequences.
Using '--unicode=highlight' will display them as Unicode escape sequences
highlighted in red, if supported by the output device.

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.");

  script_tag(name:"affected", value:"'binutils' package(s) on CentOS 7.");

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

if(release == "CentOS7") {

  if(!isnull(res = isrpmvuln(pkg:"binutils", rpm:"binutils~2.27~44.base.el7_9.1", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-devel", rpm:"binutils-devel~2.27~44.base.el7_9.1", rls:"CentOS7"))) {
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
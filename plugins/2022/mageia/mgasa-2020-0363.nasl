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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0363");
  script_cve_id("CVE-2020-14365", "CVE-2020-14430", "CVE-2020-14432");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-06-19 12:47:00 +0000 (Fri, 19 Jun 2020)");

  script_name("Mageia: Security Advisory (MGASA-2020-0363)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0363");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0363.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=27175");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/2NYYQP2XJB2TTRP6AKWVMBSPB2DFJNKD/");
  script_xref(name:"URL", value:"https://access.redhat.com/errata/RHSA-2020:3600");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ansible' package(s) announced via the MGASA-2020-0363 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An Improper Output Neutralization for Logs flaw was found in Ansible when using
the uri module, where sensitive data is exposed to content and json output.
This flaw allows an attacker to access the logs or outputs of performed tasks
to read keys used in playbooks from other users within the uri module. The
highest threat from this vulnerability is to data confidentiality
(CVE-2020-14430).

A flaw was found in the Ansible Engine when using module_args. Tasks executed
with check mode (--check-mode) do not properly neutralize sensitive data
exposed in the event data. This flaw allows unauthorized users to read this
data. The highest threat from this vulnerability is to confidentiality
(CVE-2020-14432).

A flaw was found in the Ansible Engine when installing packages using the dnf
module. GPG signatures are ignored during installation even when
disable_gpg_check is set to False, which is the default behavior. This flaw
leads to malicious packages being installed on the system and arbitrary code
executed via package installation scripts. The highest threat from this
vulnerability is to integrity and system availability (CVE-2020-14365).");

  script_tag(name:"affected", value:"'ansible' package(s) on Mageia 7.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"ansible", rpm:"ansible~2.7.18~1.1.mga7", rls:"MAGEIA7"))) {
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

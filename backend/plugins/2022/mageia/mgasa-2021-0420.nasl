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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0420");
  script_cve_id("CVE-2021-3447", "CVE-2021-3583");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-05 16:12:00 +0000 (Tue, 05 Oct 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0420)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0420");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0420.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=28832");
  script_xref(name:"URL", value:"https://access.redhat.com/errata/RHSA-2021:1342");
  script_xref(name:"URL", value:"https://access.redhat.com/errata/RHSA-2021:2664");
  script_xref(name:"URL", value:"https://github.com/ansible/ansible/blob/v2.9.24/changelogs/CHANGELOG-v2.9.rst");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ansible' package(s) announced via the MGASA-2021-0420 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in several ansible modules, where parameters containing
credentials, such as secrets, were being logged in plain-text on managed
nodes, as well as being made visible on the controller node when run in
verbose mode.

These parameters were not protected by the no_log feature. An attacker can
take advantage of this information to steal those credentials, provided
when they have access to the log files containing them. The highest threat
from this vulnerability is to data confidentiality. This flaw affects Red
Hat Ansible Automation Platform in versions before 1.2.2 and Ansible Tower
in versions before 3.8.2 (CVE-2021-3447).

A flaw was found in Ansible, where a user's controller is vulnerable to
template injection. This issue can occur through facts used in the template
if the user is trying to put templates in multi-line YAML strings and the
facts being handled do not routinely include special template characters.
This flaw allows attackers to perform command injection, which discloses
sensitive information. The highest threat from this vulnerability is to
confidentiality and integrity (CVE-2021-3583).");

  script_tag(name:"affected", value:"'ansible' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"ansible", rpm:"ansible~2.9.24~1.mga8", rls:"MAGEIA8"))) {
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

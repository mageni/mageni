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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0217");
  script_cve_id("CVE-2020-10684", "CVE-2020-1733", "CVE-2020-1735", "CVE-2020-1737", "CVE-2020-1739", "CVE-2020-1740", "CVE-2020-1746", "CVE-2020-1753");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-06-13 04:15:00 +0000 (Sat, 13 Jun 2020)");

  script_name("Mageia: Security Advisory (MGASA-2020-0217)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0217");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0217.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=26349");
  script_xref(name:"URL", value:"https://github.com/ansible/ansible/blob/v2.7.17/changelogs/CHANGELOG-v2.7.rst");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/FWDK3QUVBULS3Q3PQTGEKUQYPSNOU5M3/");
  script_xref(name:"URL", value:"https://access.redhat.com/errata/RHSA-2020:1544");
  script_xref(name:"URL", value:"https://access.redhat.com/errata/RHSA-2020:2142");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ansible' package(s) announced via the MGASA-2020-0217 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated ansible package fixes security vulnerabilities:

A race condition flaw was found in Ansible Engine when running a playbook
with an unprivileged become user. When Ansible needs to run a module with
become user, the temporary directory is created in /var/tmp. This directory
is created with 'umask 77 && mkdir -p <dir>', this operation does not fail
if the directory already exists and is owned by another user. An attacker
could take advantage to gain control of the become user as the target
directory can be retrieved by iterating '/proc/<pid>/cmdline'
(CVE-2020-1733).

A flaw was found in the Ansible Engine when the fetch module is used. An
attacker could intercept the module, inject a new path, and then choose a
new destination path on the controller node (CVE-2020-1735).

A flaw was found in the Ansible Engine when using the Extract-Zip function
from the win_unzip module as the extracted file(s) are not checked if they
belong to the destination folder. An attacker could take advantage of this
flaw by crafting an archive anywhere in the file system, using a path
traversal (CVE-2020-1737).

A flaw was found in Ansible Engine. When a password is set with the
argument 'password' of svn module, it is used on svn command line,
disclosing to other users within the same node. An attacker could take
advantage by reading the cmdline file from that particular PID on the
procfs (CVE-2020-1739).

A flaw was found in Ansible Engine when using Ansible Vault for editing
encrypted files. When a user executes 'ansible-vault edit', another user
on the same computer can read the old and new secret, as it is created in
a temporary file with mkstemp and the returned file descriptor is closed
and the method write_data is called to write the existing secret in the
file. This method will delete the file before recreating it insecurely
(CVE-2020-1740).

A flaw was found in the Ansible Engine when the ldap_attr and ldap_entry
community modules are used. The issue discloses the LDAP bind password to
stdout or a log file if a playbook task is written using the bind_pw in
the parameters field. The highest threat from this vulnerability is data
confidentiality (CVE-2020-1746).

A security flaw was found in the Ansible Engine when managing Kubernetes
using the k8s connection plugin. Sensitive parameters such as passwords
and tokens are passed to the kubectl command line instead of using
environment variables or an input configuration file, which is safer.
This flaw discloses passwords and tokens from the process list, and the
no_log directive from the debug module would not be reflected in the
underlying command-line tools options, displaying passwords and tokens
on stdout and log files (CVE-2020-1753).

A flaw was found in the Ansible Engine. When using ansible_facts as a
subkeyof itself, and promoting it to a variable when injecting is enabled,
overwriting the ansible_facts after the clean, an ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"ansible", rpm:"ansible~2.7.18~1.mga7", rls:"MAGEIA7"))) {
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

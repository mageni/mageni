# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2023.1034");
  script_cve_id("CVE-2022-39253", "CVE-2022-39260");
  script_tag(name:"creation_date", value:"2023-01-09 15:11:01 +0000 (Mon, 09 Jan 2023)");
  script_version("2023-01-10T10:12:01+0000");
  script_tag(name:"last_modification", value:"2023-01-10 10:12:01 +0000 (Tue, 10 Jan 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-21 18:26:00 +0000 (Fri, 21 Oct 2022)");

  script_name("Huawei EulerOS: Security Advisory for git (EulerOS-SA-2023-1034)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP11\-X86_64");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2023-1034");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-1034");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'git' package(s) announced via the EulerOS-SA-2023-1034 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Git is an open source, scalable, distributed revision control system. Versions prior to 2.30.6, 2.31.5, 2.32.4, 2.33.5, 2.34.5, 2.35.5, 2.36.3, and 2.37.4 are subject to exposure of sensitive information to a malicious actor. When performing a local clone (where the source and target of the clone are on the same volume), Git copies the contents of the source's `$GIT_DIR/objects` directory into the destination by either creating hardlinks to the source contents, or copying them (if hardlinks are disabled via `--no-hardlinks`). A malicious actor could convince a victim to clone a repository with a symbolic link pointing at sensitive information on the victim's machine. This can be done either by having the victim clone a malicious repository on the same machine, or having them clone a malicious repository embedded as a bare repository via a submodule from any source, provided they clone with the `--recurse-submodules` option. Git does not create symbolic links in the `$GIT_DIR/objects` directory. The problem has been patched in the versions published on 2022-10-18, and backported to v2.30.x. Potential workarounds: Avoid cloning untrusted repositories using the `--local` optimization when on a shared machine, either by passing the `--no-local` option to `git clone` or cloning from a URL that uses the `file://` scheme. Alternatively, avoid cloning repositories from untrusted sources with `--recurse-submodules` or run `git config --global protocol.file.allow user`.(CVE-2022-39253)

Git is an open source, scalable, distributed revision control system. `git shell` is a restricted login shell that can be used to implement Git's push/pull functionality via SSH. In versions prior to 2.30.6, 2.31.5, 2.32.4, 2.33.5, 2.34.5, 2.35.5, 2.36.3, and 2.37.4, the function that splits the command arguments into an array improperly uses an `int` to represent the number of entries in the array, allowing a malicious actor to intentionally overflow the return value, leading to arbitrary heap writes. Because the resulting array is then passed to `execv()`, it is possible to leverage this attack to gain remote code execution on a victim machine. Note that a victim must first allow access to `git shell` as a login shell in order to be vulnerable to this attack. This problem is patched in versions 2.30.6, 2.31.5, 2.32.4, 2.33.5, 2.34.5, 2.35.5, 2.36.3, and 2.37.4 and users are advised to upgrade to the latest version. Disabling `git shell` access via remote logins is a viable short-term workaround.(CVE-2022-39260)");

  script_tag(name:"affected", value:"'git' package(s) on Huawei EulerOS V2.0SP11(x86_64).");

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

if(release == "EULEROS-2.0SP11-x86_64") {

  if(!isnull(res = isrpmvuln(pkg:"git", rpm:"git~2.33.0~1.h5.eulerosv2r11", rls:"EULEROS-2.0SP11-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-help", rpm:"git-help~2.33.0~1.h5.eulerosv2r11", rls:"EULEROS-2.0SP11-x86_64"))) {
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

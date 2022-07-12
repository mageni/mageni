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
  script_oid("1.3.6.1.4.1.25623.1.0.845289");
  script_version("2022-03-24T14:03:56+0000");
  script_cve_id("CVE-2018-9861", "CVE-2020-9281", "CVE-2021-32808", "CVE-2021-32809", "CVE-2021-33829", "CVE-2021-37695");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-03-25 11:41:51 +0000 (Fri, 25 Mar 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-07-18 13:15:00 +0000 (Thu, 18 Jul 2019)");
  script_tag(name:"creation_date", value:"2022-03-23 02:00:50 +0000 (Wed, 23 Mar 2022)");
  script_name("Ubuntu: Security Advisory for ckeditor (USN-5340-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=(UBUNTU21\.10|UBUNTU18\.04 LTS|UBUNTU20\.04 LTS)");

  script_xref(name:"Advisory-ID", value:"USN-5340-1");
  script_xref(name:"URL", value:"https://lists.ubuntu.com/archives/ubuntu-security-announce/2022-March/006463.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ckeditor'
  package(s) announced via the USN-5340-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Kyaw Min Thein discovered that CKEditor incorrectly handled
certain inputs. An attacker could possibly use this issue
to execute arbitrary code. This issue only affects
Ubuntu 18.04 LTS. (CVE-2018-9861)

Micha Bentkowski discovered that CKEditor incorrectly handled
certain inputs. An attacker could possibly use this issue to
execute arbitrary code. This issue only affects
Ubuntu 18.04 LTS and Ubuntu 20.04 LTS. (CVE-2020-9281)

Anton Subbotin discovered that CKEditor incorrectly handled
certain inputs. An attacker could possibly use this issue to
execute arbitrary code. This issue only affects
Ubuntu 21.10. (CVE-2021-32808)

Anton Subbotin discovered that CKEditor incorrectly handled
certain inputs. An attacker could possibly use this issue to
inject arbitrary code. (CVE-2021-32809)

Or Sahar discovered that CKEditor incorrectly handled certain
inputs. An attacker could possibly use this issue to execute
arbitrary code. This issue only affects
Ubuntu 18.04 LTS and Ubuntu 20.04 LTS. (CVE-2021-33829)

Mika Kulmala discovered that CKEditor incorrectly handled
certain inputs. An attacker could possibly use this issue to
execute arbitrary code. (CVE-2021-37695)");

  script_tag(name:"affected", value:"'ckeditor' package(s) on Ubuntu 21.10, Ubuntu 20.04 LTS, Ubuntu 18.04 LTS.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "UBUNTU21.10") {

  if(!isnull(res = isdpkgvuln(pkg:"ckeditor", ver:"4.16.0+dfsg-2ubuntu0.1", rls:"UBUNTU21.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"ckeditor", ver:"4.5.7+dfsg-2ubuntu0.18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"ckeditor", ver:"4.12.1+dfsg-1ubuntu0.1", rls:"UBUNTU20.04 LTS"))) {
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
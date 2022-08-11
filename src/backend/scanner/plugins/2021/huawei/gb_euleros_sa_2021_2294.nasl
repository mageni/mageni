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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2021.2294");
  script_cve_id("CVE-2021-21261");
  script_tag(name:"creation_date", value:"2021-08-09 10:12:21 +0000 (Mon, 09 Aug 2021)");
  script_version("2021-08-09T11:38:50+0000");
  script_tag(name:"last_modification", value:"2021-08-10 10:38:07 +0000 (Tue, 10 Aug 2021)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-27 19:34:00 +0000 (Wed, 27 Jan 2021)");

  script_name("Huawei EulerOS: Security Advisory for flatpak (EulerOS-SA-2021-2294)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP8");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2021-2294");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2294");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'flatpak' package(s) announced via the EulerOS-SA-2021-2294 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Flatpak is a system for building, distributing, and running sandboxed desktop applications on Linux. A bug was discovered in the `flatpak-portal` service that can allow sandboxed applications to execute arbitrary code on the host system (a sandbox escape). This sandbox-escape bug is present in versions from 0.11.4 and before fixed versions 1.8.5 and 1.10.0. The Flatpak portal D-Bus service (`flatpak-portal`, also known by its D-Bus service name `org.freedesktop.portal.Flatpak`) allows apps in a Flatpak sandbox to launch their own subprocesses in a new sandbox instance, either with the same security settings as the caller or with more restrictive security settings. For example, this is used in Flatpak-packaged web browsers such as Chromium to launch subprocesses that will process untrusted web content, and give those subprocesses a more restrictive sandbox than the browser itself. In vulnerable versions, the Flatpak portal service passes caller-specified environment variables to non-sandboxed processes on the host system, and in particular to the `flatpak run` command that is used to launch the new sandbox instance. A malicious or compromised Flatpak app could set environment variables that are trusted by the `flatpak run` command, and use them to execute arbitrary code that is not in a sandbox. As a workaround, this vulnerability can be mitigated by preventing the `flatpak-portal` service from starting, but that mitigation will prevent many Flatpak apps from working correctly. This is fixed in versions 1.8.5 and 1.10.0.(CVE-2021-21261)");

  script_tag(name:"affected", value:"'flatpak' package(s) on Huawei EulerOS V2.0SP8.");

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

if(release == "EULEROS-2.0SP8") {

  if(!isnull(res = isrpmvuln(pkg:"flatpak", rpm:"flatpak~1.0.3~1.h4.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flatpak-libs", rpm:"flatpak-libs~1.0.3~1.h4.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
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

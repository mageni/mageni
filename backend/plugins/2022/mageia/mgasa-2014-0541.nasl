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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0541");
  script_cve_id("CVE-2014-9293", "CVE-2014-9294", "CVE-2014-9295", "CVE-2014-9296");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-01-03 02:59:00 +0000 (Tue, 03 Jan 2017)");

  script_name("Mageia: Security Advisory (MGASA-2014-0541)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0541");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0541.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=14858");
  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/SecurityNotice#Resolved_Vulnerabilities");
  script_xref(name:"URL", value:"https://ics-cert.us-cert.gov/advisories/ICSA-14-353-01");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/852879");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1176032");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1176035");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1176037");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1176040");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ntp' package(s) announced via the MGASA-2014-0541 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated ntp packages fix security vulnerabilities:

If no authentication key is defined in the ntp.conf file, a
cryptographically-weak default key is generated (CVE-2014-9293).

ntp-keygen before 4.2.7p230 uses a non-cryptographic random number generator
with a weak seed to generate symmetric keys (CVE-2014-9294).

A remote unauthenticated attacker may craft special packets that trigger
buffer overflows in the ntpd functions crypto_recv() (when using autokey
authentication), ctl_putdata(), and configure(). The resulting buffer
overflows may be exploited to allow arbitrary malicious code to be executed
with the privilege of the ntpd process (CVE-2014-9295).

A section of code in ntpd handling a rare error is missing a return
statement, therefore processing did not stop when the error was encountered.
This situation may be exploitable by an attacker (CVE-2014-9296).

The ntp package has been patched to fix these issues.");

  script_tag(name:"affected", value:"'ntp' package(s) on Mageia 4.");

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

  if(!isnull(res = isrpmvuln(pkg:"ntp", rpm:"ntp~4.2.6p5~15.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntp-client", rpm:"ntp-client~4.2.6p5~15.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntp-doc", rpm:"ntp-doc~4.2.6p5~15.2.mga4", rls:"MAGEIA4"))) {
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

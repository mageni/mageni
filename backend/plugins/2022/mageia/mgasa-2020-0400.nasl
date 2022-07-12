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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0400");
  script_cve_id("CVE-2020-12670", "CVE-2020-8820", "CVE-2020-8821");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-16 16:15:00 +0000 (Fri, 16 Oct 2020)");

  script_name("Mageia: Security Advisory (MGASA-2020-0400)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0400");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0400.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=27459");
  script_xref(name:"URL", value:"https://www.webmin.com/security.html");
  script_xref(name:"URL", value:"https://www.webmin.com/changes.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'webmin' package(s) announced via the MGASA-2020-0400 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An XSS Vulnerability exists in Webmin 1.941 and earlier affecting the Cluster
Shell Commands Endpoint. A user may enter any XSS Payload into the Command
field and execute it. Then, after revisiting the Cluster Shell Commands Menu,
the XSS Payload will be rendered and executed. (CVE-2020-8820)

An Improper Data Validation Vulnerability exists in Webmin 1.941 and earlier
affecting the Command Shell Endpoint. A user may enter HTML code into the
Command field and submit it. Then, after visiting the Action Logs Menu and
displaying logs, the HTML code will be rendered (however, JavaScript is not
executed). Changes are kept across users. (CVE-2020-8821)

XSS exists in Webmin 1.941 and earlier affecting the Save function of the
Read User Email Module / mailboxes Endpoint when attempting to save HTML
emails. This module parses any output without sanitizing SCRIPT elements, as
opposed to the View function, which sanitizes the input correctly. A malicious
user can send any JavaScript payload into the message body and execute it if
the user decides to save that email. (CVE-2020-12670)");

  script_tag(name:"affected", value:"'webmin' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"webmin", rpm:"webmin~1.960~1.mga7", rls:"MAGEIA7"))) {
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

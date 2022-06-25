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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0153");
  script_cve_id("CVE-2015-3008");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-31T07:41:30+0000");
  script_tag(name:"last_modification", value:"2022-01-31 07:41:30 +0000 (Mon, 31 Jan 2022)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-09 19:56:00 +0000 (Tue, 09 Oct 2018)");

  script_name("Mageia: Security Advisory (MGASA-2015-0153)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0153");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0153.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=15674");
  script_xref(name:"URL", value:"http://downloads.asterisk.org/pub/security/AST-2015-003.html");
  script_xref(name:"URL", value:"http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLog-11.17.1");
  script_xref(name:"URL", value:"http://downloads.asterisk.org/pub/telephony/asterisk/asterisk-11.17.1-summary.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'asterisk' package(s) announced via the MGASA-2015-0153 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated asterisk packages fix security vulnerability:

When Asterisk registers to a SIP TLS device and verifies the server,
Asterisk will accept signed certificates that match a common name other than
the one Asterisk is expecting if the signed certificate has a common name
containing a null byte after the portion of the common name that Asterisk
expected (CVE-2015-3008).");

  script_tag(name:"affected", value:"'asterisk' package(s) on Mageia 4.");

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

  if(!isnull(res = isrpmvuln(pkg:"asterisk", rpm:"asterisk~11.17.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-addons", rpm:"asterisk-addons~11.17.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-devel", rpm:"asterisk-devel~11.17.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-firmware", rpm:"asterisk-firmware~11.17.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-gui", rpm:"asterisk-gui~11.17.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-plugins-alsa", rpm:"asterisk-plugins-alsa~11.17.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-plugins-calendar", rpm:"asterisk-plugins-calendar~11.17.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-plugins-cel", rpm:"asterisk-plugins-cel~11.17.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-plugins-corosync", rpm:"asterisk-plugins-corosync~11.17.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-plugins-curl", rpm:"asterisk-plugins-curl~11.17.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-plugins-dahdi", rpm:"asterisk-plugins-dahdi~11.17.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-plugins-fax", rpm:"asterisk-plugins-fax~11.17.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-plugins-festival", rpm:"asterisk-plugins-festival~11.17.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-plugins-ices", rpm:"asterisk-plugins-ices~11.17.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-plugins-jabber", rpm:"asterisk-plugins-jabber~11.17.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-plugins-jack", rpm:"asterisk-plugins-jack~11.17.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-plugins-ldap", rpm:"asterisk-plugins-ldap~11.17.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-plugins-lua", rpm:"asterisk-plugins-lua~11.17.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-plugins-minivm", rpm:"asterisk-plugins-minivm~11.17.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-plugins-mobile", rpm:"asterisk-plugins-mobile~11.17.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-plugins-mp3", rpm:"asterisk-plugins-mp3~11.17.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-plugins-mysql", rpm:"asterisk-plugins-mysql~11.17.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-plugins-ooh323", rpm:"asterisk-plugins-ooh323~11.17.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-plugins-osp", rpm:"asterisk-plugins-osp~11.17.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-plugins-oss", rpm:"asterisk-plugins-oss~11.17.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-plugins-pgsql", rpm:"asterisk-plugins-pgsql~11.17.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-plugins-pktccops", rpm:"asterisk-plugins-pktccops~11.17.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-plugins-portaudio", rpm:"asterisk-plugins-portaudio~11.17.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-plugins-radius", rpm:"asterisk-plugins-radius~11.17.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-plugins-saycountpl", rpm:"asterisk-plugins-saycountpl~11.17.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-plugins-skinny", rpm:"asterisk-plugins-skinny~11.17.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-plugins-snmp", rpm:"asterisk-plugins-snmp~11.17.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-plugins-speex", rpm:"asterisk-plugins-speex~11.17.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-plugins-sqlite", rpm:"asterisk-plugins-sqlite~11.17.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-plugins-tds", rpm:"asterisk-plugins-tds~11.17.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-plugins-unistim", rpm:"asterisk-plugins-unistim~11.17.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-plugins-voicemail", rpm:"asterisk-plugins-voicemail~11.17.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-plugins-voicemail-imap", rpm:"asterisk-plugins-voicemail-imap~11.17.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asterisk-plugins-voicemail-plain", rpm:"asterisk-plugins-voicemail-plain~11.17.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64asteriskssl1", rpm:"lib64asteriskssl1~11.17.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasteriskssl1", rpm:"libasteriskssl1~11.17.1~1.mga4", rls:"MAGEIA4"))) {
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

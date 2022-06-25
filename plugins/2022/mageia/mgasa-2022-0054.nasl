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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0054");
  script_cve_id("CVE-2021-20316", "CVE-2021-44141", "CVE-2021-44142", "CVE-2022-0336");
  script_tag(name:"creation_date", value:"2022-02-11 03:16:20 +0000 (Fri, 11 Feb 2022)");
  script_version("2022-02-11T03:16:20+0000");
  script_tag(name:"last_modification", value:"2022-02-14 11:09:18 +0000 (Mon, 14 Feb 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"Greenbone");
  script_tag(name:"severity_date", value:"2022-02-11 03:16:20 +0000 (Fri, 11 Feb 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0054)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0054");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0054.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29974");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2021-44141.html");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2021-44142.html");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2022-0336.html");
  script_xref(name:"URL", value:"https://www.samba.org/samba/history/samba-4.14.12.html");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5260-1");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2021-20316.html");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2022-February/010164.html");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/72ZRNFZ3DE3TJA7HFCVV476YJN6I4B5M/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'samba' package(s) announced via the MGASA-2022-0054 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"For CVE-2021-20316 and CVE-2021-44141, there is only a workaround and
mitigation:

All versions of Samba prior to 4.15.5 are vulnerable to a malicious
client using a server symlink to determine if a file or directory
exists in an area of the server file system not exported under the
share definition. SMB1 with unix extensions has to be enabled in order
for this attack to succeed.

Clients that have write access to the exported part of the file system
under a share via SMB1 unix extensions or via NFS can create symlinks
that point to arbitrary files or directories on the server filesystem.

Clients can then use SMB1 unix extension information queries to
determine if the target of the symlink exists or not by examining
error codes returned from the smbd server. There is no ability to
access these files or directories, only to determine if they exist or
not.

If SMB1 is turned off and only SMB2 is used, or unix extensions are
not enabled then there is no way to discover if a symlink points to a
valid target or not via SMB2. For this reason, even if symlinks are
created via NFS, if the Samba server does not allow SMB1 with unix
extensions there is no way to exploit this bug.

Finding out what files or directories exist on a file server can help
attackers guess system user names or the exact operating system
release and applications running on the server hosting Samba which may
help mount further attacks.

SMB1 has been disabled on Samba since version 4.11.0 and
onwards. Exploitation of this bug has not been seen in the wild.

For CVE-2021-44142, All versions of Samba prior to 4.13.17 are vulnerable
to an out-of-bounds heap read write vulnerability that allows remote
attackers to execute arbitrary code as root on affected Samba
installations that use the VFS module vfs_fruit.

The specific flaw exists within the parsing of EA metadata when
opening files in smbd. Access as a user that has write access to a
file's extended attributes is required to exploit this
vulnerability. Note that this could be a guest or unauthenticated user
if such users are allowed write access to file extended attributes.

The problem in vfs_fruit exists in the default configuration of the
fruit VFS module using fruit:metadata=netatalk or fruit:resource=file.
If both options are set to different settings than the default values,
the system is not affected by the security issue.

For CVE-2022-0336, The Samba AD DC includes checks when adding service
principals names (SPNs) to an account to ensure that SPNs do not alias
with those already in the database. Some of these checks are able to be
bypassed if an account modification re-adds an SPN that was previously
present on that account, such as one added when a computer is joined to
a domain.

An attacker who has the ability to write to an account can exploit
this to perform a denial-of-service attack by adding an SPN that
matches an existing service. ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'samba' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"ctdb", rpm:"ctdb~4.14.12~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64heimntlm-samba4_1", rpm:"lib64heimntlm-samba4_1~4.14.12~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kdc-samba4_2", rpm:"lib64kdc-samba4_2~4.14.12~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64samba-dc0", rpm:"lib64samba-dc0~4.14.12~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64samba-devel", rpm:"lib64samba-devel~4.14.12~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64samba-test0", rpm:"lib64samba-test0~4.14.12~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64samba1", rpm:"lib64samba1~4.14.12~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64smbclient-devel", rpm:"lib64smbclient-devel~4.14.12~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64smbclient0", rpm:"lib64smbclient0~4.14.12~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wbclient-devel", rpm:"lib64wbclient-devel~4.14.12~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wbclient0", rpm:"lib64wbclient0~4.14.12~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libheimntlm-samba4_1", rpm:"libheimntlm-samba4_1~4.14.12~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkdc-samba4_2", rpm:"libkdc-samba4_2~4.14.12~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-dc0", rpm:"libsamba-dc0~4.14.12~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-devel", rpm:"libsamba-devel~4.14.12~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-test0", rpm:"libsamba-test0~4.14.12~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba1", rpm:"libsamba1~4.14.12~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbclient-devel", rpm:"libsmbclient-devel~4.14.12~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbclient0", rpm:"libsmbclient0~4.14.12~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwbclient-devel", rpm:"libwbclient-devel~4.14.12~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwbclient0", rpm:"libwbclient0~4.14.12~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-samba", rpm:"python3-samba~4.14.12~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba", rpm:"samba~4.14.12~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client", rpm:"samba-client~4.14.12~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-common", rpm:"samba-common~4.14.12~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-dc", rpm:"samba-dc~4.14.12~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-krb5-printing", rpm:"samba-krb5-printing~4.14.12~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-test", rpm:"samba-test~4.14.12~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind", rpm:"samba-winbind~4.14.12~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-clients", rpm:"samba-winbind-clients~4.14.12~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-krb5-locator", rpm:"samba-winbind-krb5-locator~4.14.12~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-modules", rpm:"samba-winbind-modules~4.14.12~1.mga8", rls:"MAGEIA8"))) {
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

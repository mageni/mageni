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
  script_oid("1.3.6.1.4.1.25623.1.0.854233");
  script_version("2021-10-28T14:01:13+0000");
  script_cve_id("CVE-2018-15473");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-10-29 11:15:42 +0000 (Fri, 29 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2021-10-19 01:03:16 +0000 (Tue, 19 Oct 2021)");
  script_name("openSUSE: Security Advisory for ssh-audit (openSUSE-SU-2021:1383-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:1383-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/HMNIMCAHIBHI4ABCI2JE3E6E2SYDAP2T");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ssh-audit'
  package(s) announced via the openSUSE-SU-2021:1383-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ssh-audit fixes the following issues:

     ssh-audit was updated to version 2.5.0

  * Fixed crash when running host key tests.

  * Handles server connection failures more gracefully.

  * Now prints JSON with indents when -jj is used (useful for debugging).

  * Added MD5 fingerprints to verbose output.

  * Added -d/--debug option for getting debugging output.

  * Updated JSON output to include MD5 fingerprints. Note that this results
       in a breaking change in the &#x27 fingerprints&#x27  dictionary format.

  * Updated OpenSSH 8.1 (and earlier) policies to include rsa-sha2-512 and
       rsa-sha2-256.

  * Added OpenSSH v8.6 &amp  v8.7 policies.

  * Added 3 new key exchanges:

       + gss-gex-sha1-eipGX3TCiQSrx573bT1o1Q==
       + gss-group1-sha1-eipGX3TCiQSrx573bT1o1Q==
       + gss-group14-sha1-eipGX3TCiQSrx573bT1o1Q==

  * Added 3 new MACs:

       + hmac-ripemd160-96
       + AEAD_AES_128_GCM
       + AEAD_AES_256_GCM

     Update to version 2.4.0

  * Added multi-threaded scanning support.

  * Added version check for OpenSSH user enumeration (CVE-2018-15473).

  * Added deprecation note to host key types based on SHA-1.

  * Added extra warnings for SSHv1.

  * Added built-in hardened OpenSSH v8.5 policy.

  * Upgraded warnings to failures for host key types based on SHA-1

  * Fixed crash when receiving unexpected response during host key test.

  * Fixed hang against older Cisco devices during host key test &amp  gex test.

  * Fixed improper termination while scanning multiple targets when
       one target returns an error.

  * Dropped support for Python 3.5 (which reached EOL in Sept.2020)

  * Added 1 new key exchange: sntrup761x25519-sha512(a)openssh.com.

     Update to version 2.3.1

  * Now parses public key sizes for rsa-sha2-256-cert-v01(a)openssh.com and
       rsa-sha2-512-cert-v01(a)openssh.com host key types.

  * Flag ssh-rsa-cert-v01(a)openssh.com as a failure due to SHA-1 hash.

  * Fixed bug in recommendation output which suppressed some algorithms
       inappropriately.

  * Built-in policies now include CA key requirements (if certificates are
       in use).

  * Lookup function (--lookup) now performs case-insensitive lookups of
       similar algorithms.

  * Migrated pre-made policies from external files to internal database.

  * Split single 3,500 line script into many files (by class).

  * Added setup.py support

  * Added 1 new cipher: des-cbc(a)ssh.com.

     Update to version 2.3.0

     The highlight of this release is support for policy scanning (th ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'ssh-audit' package(s) on openSUSE Leap 15.2.");

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

if(release == "openSUSELeap15.2") {

  if(!isnull(res = isrpmvuln(pkg:"ssh-audit", rpm:"ssh-audit~2.5.0~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
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
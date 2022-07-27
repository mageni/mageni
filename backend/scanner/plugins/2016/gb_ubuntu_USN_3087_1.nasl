###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for openssl USN-3087-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842896");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-09-23 05:42:26 +0200 (Fri, 23 Sep 2016)");
  script_cve_id("CVE-2016-6304", "CVE-2016-2177", "CVE-2016-2178", "CVE-2016-2179",
  		"CVE-2016-2180", "CVE-2016-2181", "CVE-2016-2182", "CVE-2016-2183",
  		"CVE-2016-6302", "CVE-2016-6303", "CVE-2016-6306");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for openssl USN-3087-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Shi Lei discovered that OpenSSL incorrectly
  handled the OCSP Status Request extension. A remote attacker could possibly use
  this issue to cause memory consumption, resulting in a denial of service.
  (CVE-2016-6304)

Guido Vranken discovered that OpenSSL used undefined behaviour when
performing pointer arithmetic. A remote attacker could possibly use this
issue to cause OpenSSL to crash, resulting in a denial of service. This
issue has only been addressed in Ubuntu 16.04 LTS in this update.
(CVE-2016-2177)

C&#233 sar Pereida, Billy Brumley, and Yuval Yarom discovered that OpenSSL
did not properly use constant-time operations when performing DSA signing.
A remote attacker could possibly use this issue to perform a cache-timing
attack and recover private DSA keys. (CVE-2016-2178)

Quan Luo discovered that OpenSSL did not properly restrict the lifetime
of queue entries in the DTLS implementation. A remote attacker could
possibly use this issue to consume memory, resulting in a denial of
service. (CVE-2016-2179)

Shi Lei discovered that OpenSSL incorrectly handled memory in the
TS_OBJ_print_bio() function. A remote attacker could possibly use this
issue to cause a denial of service. (CVE-2016-2180)

It was discovered that the OpenSSL incorrectly handled the DTLS anti-replay
feature. A remote attacker could possibly use this issue to cause a denial
of service. (CVE-2016-2181)

Shi Lei discovered that OpenSSL incorrectly validated division results. A
remote attacker could possibly use this issue to cause a denial of service.
(CVE-2016-2182)

Karthik Bhargavan and Gaetan Leurent discovered that the DES and Triple DES
ciphers were vulnerable to birthday attacks. A remote attacker could
possibly use this flaw to obtain clear text data from long encrypted
sessions. This update moves DES from the HIGH cipher list to MEDIUM.
(CVE-2016-2183)

Shi Lei discovered that OpenSSL incorrectly handled certain ticket lengths.
A remote attacker could use this issue to cause a denial of service.
(CVE-2016-6302)

Shi Lei discovered that OpenSSL incorrectly handled memory in the
MDC2_Update() function. A remote attacker could possibly use this issue to
cause a denial of service. (CVE-2016-6303)

Shi Lei discovered that OpenSSL incorrectly performed certain message
length checks. A remote attacker could possibly use this issue to cause a
denial of service. (CVE-2016-6306)");
  script_tag(name:"affected", value:"openssl on Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-3087-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04 LTS|12\.04 LTS|16\.04 LTS)");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "UBUNTU14.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libssl1.0.0:i386", ver:"1.0.1f-1ubuntu2.20", rls:"UBUNTU14.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libssl1.0.0:amd64", ver:"1.0.1f-1ubuntu2.20", rls:"UBUNTU14.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libssl1.0.0:i386", ver:"1.0.1-4ubuntu5.37", rls:"UBUNTU12.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libssl1.0.0:amd64", ver:"1.0.1-4ubuntu5.37", rls:"UBUNTU12.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU16.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libssl1.0.0:i386", ver:"1.0.2g-1ubuntu4.4", rls:"UBUNTU16.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libssl1.0.0:amd64", ver:"1.0.2g-1ubuntu4.4", rls:"UBUNTU16.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1192_3.nasl 14132 2019-03-13 09:25:59Z cfischer $
#
# Ubuntu Update for libvoikko USN-1192-3
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-1192-3/");
  script_oid("1.3.6.1.4.1.25623.1.0.840777");
  script_version("$Revision: 14132 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-10-21 16:31:29 +0200 (Fri, 21 Oct 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2011-2989", "CVE-2011-2991", "CVE-2011-2985", "CVE-2011-2993",
                "CVE-2011-2988", "CVE-2011-2987", "CVE-2011-0084", "CVE-2011-2990");
  script_name("Ubuntu Update for libvoikko USN-1192-3");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU11\.04");
  script_tag(name:"summary", value:"Ubuntu Update for Linux kernel vulnerabilities USN-1192-3");
  script_tag(name:"affected", value:"libvoikko on Ubuntu 11.04");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"USN-1192-1 provided Firefox 6 as a security upgrade. Unfortunately, this
  caused a regression in libvoikko which caused Firefox to crash while spell
  checking words with hyphens. This update corrects the issue. We apologize
  for the inconvenience.

  Original advisory details:

  Aral Yaman discovered a vulnerability in the WebGL engine. An attacker
  could potentially use this to crash Firefox or execute arbitrary code with
  the privileges of the user invoking Firefox. (CVE-2011-2989)

  Vivekanand Bolajwar discovered a vulnerability in the JavaScript engine. An
  attacker could potentially use this to crash Firefox or execute arbitrary
  code with the privileges of the user invoking Firefox. (CVE-2011-2991)

  Bert Hubert and Theo Snelleman discovered a vulnerability in the Ogg
  reader. An attacker could potentially use this to crash Firefox or execute
  arbitrary code with the privileges of the user invoking Firefox.
  (CVE-2011-2991)

  Robert Kaiser, Jesse Ruderman, Gary Kwong, Christoph Diehl, Martijn
  Wargers, Travis Emmitt, Bob Clary, and Jonathan Watt discovered multiple
  memory vulnerabilities in the browser rendering engine. An attacker could
  use these to possibly execute arbitrary code with the privileges of the
  user invoking Firefox. (CVE-2011-2985)

  Rafael Gieschke discovered that unsigned JavaScript could call into a
  script inside a signed JAR. This could allow an attacker to execute
  arbitrary code with the identity and permissions of the signed JAR.
  (CVE-2011-2993)

  Michael Jordon discovered that an overly long shader program could cause a
  buffer overrun. An attacker could potentially use this to crash Firefox or
  execute arbitrary code with the privileges of the user invoking Firefox.
  (CVE-2011-2988)

  Michael Jordon discovered a heap overflow in the ANGLE library used in
  Firefox's WebGL implementation. An attacker could potentially use this to
  crash Firefox or execute arbitrary code with the privileges of the user
  invoking Firefox. (CVE-2011-2987)

  It was discovered that an SVG text manipulation routine contained a
  dangling pointer vulnerability. An attacker could potentially use this to
  crash Firefox or execute arbitrary code with the privileges of the user
  invoking Firefox. (CVE-2011-0084)

  Mike Cardwell discovered that Content Security Policy violation reports
  failed to strip out proxy authorization credentials from the list of
  request headers. This could allow a malicious website to capture proxy
  authorization credentials. Daniel Veditz discovered that redirecting to a
  website with Content Security  ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "UBUNTU11.04")
{

  if ((res = isdpkgvuln(pkg:"libvoikko1", ver:"3.1-1ubuntu0.1", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}

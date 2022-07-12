###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1256_1.nasl 14132 2019-03-13 09:25:59Z cfischer $
#
# Ubuntu Update for linux-lts-backport-natty USN-1256-1
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
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-1256-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.840802");
  script_version("$Revision: 14132 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-11-11 09:55:49 +0530 (Fri, 11 Nov 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2011-1020", "CVE-2011-1078", "CVE-2011-1079", "CVE-2011-1080",
                "CVE-2011-1093", "CVE-2011-1160", "CVE-2011-1180", "CVE-2011-1478",
                "CVE-2010-4250", "CVE-2011-1479", "CVE-2011-1493", "CVE-2011-1573",
                "CVE-2011-1576", "CVE-2011-1577", "CVE-2011-1581", "CVE-2011-1585",
                "CVE-2011-1767", "CVE-2011-1768", "CVE-2011-1771", "CVE-2011-1776",
                "CVE-2011-1833", "CVE-2011-2183", "CVE-2011-2213", "CVE-2011-2479",
                "CVE-2011-2484", "CVE-2011-2491", "CVE-2011-2492", "CVE-2011-2493",
                "CVE-2011-2494", "CVE-2011-2495", "CVE-2011-2496", "CVE-2011-2497",
                "CVE-2011-2517", "CVE-2011-2525", "CVE-2011-2689", "CVE-2011-2695",
                "CVE-2011-2699", "CVE-2011-2700", "CVE-2011-2723", "CVE-2011-2905",
                "CVE-2011-2909", "CVE-2011-2918", "CVE-2011-2928", "CVE-2011-2942",
                "CVE-2011-3188", "CVE-2011-3191", "CVE-2011-3209", "CVE-2011-3363");
  script_name("Ubuntu Update for linux-lts-backport-natty USN-1256-1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU10\.04 LTS");
  script_tag(name:"summary", value:"Ubuntu Update for Linux kernel vulnerabilities USN-1256-1");
  script_tag(name:"affected", value:"linux-lts-backport-natty on Ubuntu 10.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"It was discovered that the /proc filesystem did not correctly handle
  permission changes when programs executed. A local attacker could hold open
  files to examine details about programs running with higher privileges,
  potentially increasing the chances of exploiting additional
  vulnerabilities. (CVE-2011-1020)

  Vasiliy Kulikov discovered that the Bluetooth stack did not correctly clear
  memory. A local attacker could exploit this to read kernel stack memory,
  leading to a loss of privacy. (CVE-2011-1078)

  Vasiliy Kulikov discovered that the Bluetooth stack did not correctly check
  that device name strings were NULL terminated. A local attacker could
  exploit this to crash the system, leading to a denial of service, or leak
  contents of kernel stack memory, leading to a loss of privacy.
  (CVE-2011-1079)

  Vasiliy Kulikov discovered that bridge network filtering did not check that
  name fields were NULL terminated. A local attacker could exploit this to
  leak contents of kernel stack memory, leading to a loss of privacy.
  (CVE-2011-1080)

  Johan Hovold discovered that the DCCP network stack did not correctly
  handle certain packet combinations. A remote attacker could send specially
  crafted network traffic that would crash the system, leading to a denial of
  service. (CVE-2011-1093)

  Peter Huewe discovered that the TPM device did not correctly initialize
  memory. A local attacker could exploit this to read kernel heap memory
  contents, leading to a loss of privacy. (CVE-2011-1160)

  Dan Rosenberg discovered that the IRDA subsystem did not correctly check
  certain field sizes. If a system was using IRDA, a remote attacker could
  send specially crafted traffic to crash the system or gain root privileges.
  (CVE-2011-1180)

  Ryan Sweat discovered that the GRO code did not correctly validate memory.
  In some configurations on systems using VLANs, a remote attacker could send
  specially crafted traffic to crash the system, leading to a denial of
  service. (CVE-2011-1478)

  It was discovered that the security fix for CVE-2010-4250 introduced a
  regression. A remote attacker could exploit this to crash the system,
  leading to a denial of service. (CVE-2011-1479)

  Dan Rosenberg discovered that the X.25 Rose network stack did not correctly
  handle certain fields. If a system was running with Rose enabled, a remote
  attacker could send specially crafted traffic to gain root privileges.
  (CVE-2011-1493)

  It was discovered that the Stream Control Transmission Protocol (SCTP)
  implementation incorrectly calculated length ...

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

if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.38-12-generic", ver:"2.6.38-12.51~lucid1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.38-12-generic-pae", ver:"2.6.38-12.51~lucid1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.38-12-server", ver:"2.6.38-12.51~lucid1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.38-12-virtual", ver:"2.6.38-12.51~lucid1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}

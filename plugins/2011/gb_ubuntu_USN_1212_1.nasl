###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1212_1.nasl 14132 2019-03-13 09:25:59Z cfischer $
#
# Ubuntu Update for linux-ti-omap4 USN-1212-1
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
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-1212-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.840748");
  script_version("$Revision: 14132 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-09-23 16:39:49 +0200 (Fri, 23 Sep 2011)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2011-0463", "CVE-2011-1017", "CVE-2011-1020", "CVE-2011-1078", "CVE-2011-1079", "CVE-2011-1080", "CVE-2011-1160", "CVE-2011-1170", "CVE-2011-1171", "CVE-2011-1172", "CVE-2011-2534", "CVE-2011-1173", "CVE-2011-1180", "CVE-2011-1182", "CVE-2011-1493", "CVE-2011-1494", "CVE-2011-1495", "CVE-2011-1577", "CVE-2011-1581", "CVE-2011-1593", "CVE-2011-1598", "CVE-2011-1748", "CVE-2011-1745", "CVE-2011-2022", "CVE-2011-1746", "CVE-2011-1770", "CVE-2011-1771", "CVE-2011-1833", "CVE-2011-2484", "CVE-2011-2492", "CVE-2011-2493", "CVE-2011-2689", "CVE-2011-2699", "CVE-2011-2918");
  script_name("Ubuntu Update for linux-ti-omap4 USN-1212-1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU11\.04");
  script_tag(name:"summary", value:"Ubuntu Update for Linux kernel vulnerabilities USN-1212-1");
  script_tag(name:"affected", value:"linux-ti-omap4 on Ubuntu 11.04");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Goldwyn Rodrigues discovered that the OCFS2 filesystem did not correctly
  clear memory when writing certain file holes. A local attacker could
  exploit this to read uninitialized data from the disk, leading to a loss of
  privacy. (CVE-2011-0463)

  Timo Warns discovered that the LDM disk partition handling code did not
  correctly handle certain values. By inserting a specially crafted disk
  device, a local attacker could exploit this to gain root privileges.
  (CVE-2011-1017)

  It was discovered that the /proc filesystem did not correctly handle
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

  Peter Huewe discovered that the TPM device did not correctly initialize
  memory. A local attacker could exploit this to read kernel heap memory
  contents, leading to a loss of privacy. (CVE-2011-1160)

  Vasiliy Kulikov discovered that the netfilter code did not check certain
  strings copied from userspace. A local attacker with netfilter access could
  exploit this to read kernel memory or crash the system, leading to a denial
  of service. (CVE-2011-1170, CVE-2011-1171, CVE-2011-1172, CVE-2011-2534)

  Vasiliy Kulikov discovered that the Acorn Universal Networking driver did
  not correctly initialize memory. A remote attacker could send specially
  crafted traffic to read kernel stack memory, leading to a loss of privacy.
  (CVE-2011-1173)

  Dan Rosenberg discovered that the IRDA subsystem did not correctly check
  certain field sizes. If a system was using IRDA, a remote attacker could
  send specially crafted traffic to crash the system or gain root privileges.
  (CVE-2011-1180)

  Julien Tinnes discovered that the kernel d ...

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

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.38-1209-omap4", ver:"2.6.38-1209.15", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}

###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for libreswan CESA-2015:1154 centos7
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.882204");
  script_version("$Revision: 14058 $");
  script_cve_id("CVE-2015-3204");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-06-24 06:16:38 +0200 (Wed, 24 Jun 2015)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for libreswan CESA-2015:1154 centos7");
  script_tag(name:"summary", value:"Check the version of libreswan");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Libreswan is an implementation of IPsec &amp
  IKE for Linux. IPsec is the Internet Protocol Security and uses strong cryptography
  to provide both authentication and encryption services. These services allow you to
  build secure tunnels through untrusted networks such as virtual private network
  (VPN).

A flaw was discovered in the way Libreswan's IKE daemon processed certain
IKEv1 payloads. A remote attacker could send specially crafted IKEv1
payloads that, when processed, would lead to a denial of service (daemon
crash). (CVE-2015-3204)

Red Hat would like to thank Javantea for reporting this issue.

This update fixes the following bugs:

  * Previously, the programs/pluto/state.h and
programs/pluto/kernel_netlink.c files had a maximum SELinux context size
of 257 and 1024 respectively. These restrictions set by libreswan limited
the size of the context that can be exchanged by pluto (the IPSec daemon)
when using a Labeled Internet Protocol Security (IPsec). The SElinux
labels for Labeled IPsec have been extended to 4096 bytes and the
mentioned restrictions no longer exist. (BZ#1198650)

  * On some architectures, the kernel AES_GCM IPsec algorithm did not work
properly with acceleration drivers. On those kernels, some acceleration
modules are added to the modprobe blacklist. However, Libreswan was
ignoring this blacklist, leading to AES_GCM failures. This update adds
support for the module blacklist to the libreswan packages and thus
prevents the AES_GCM failures from occurring. (BZ#1208022)

  * An IPv6 issue has been resolved that prevented ipv6-icmp Neighbour
Discovery from working properly once an IPsec tunnel is established (and
one endpoint reboots). When upgrading, ensure that /etc/ipsec.conf is
loading all /etc/ipsec.d/*conf files using the /etc/ipsec.conf 'include'
statement, or explicitly include this new configuration file in
/etc/ipsec.conf. (BZ#1208023)

  * A FIPS self-test prevented libreswan from properly starting in FIPS mode.
This bug has been fixed and libreswan now works in FIPS mode as expected.
(BZ#1211146)

In addition, this update adds the following enhancements:

  * A new option 'seedbits=' has been added to pre-seed the Network Security
Services (NSS) pseudo random number generator (PRNG) function with entropy
from the /dev/random file on startup. This option is disabled by default.
It can be enabled by setting the 'seedbits=' option in the 'config setup'
section in the /etc/ipsec.conf file. (BZ#1198649)

  * The build process now runs a Cryptographic Algorithm Validation Program
(CAVP) certification test on the Internet Key Exchange version 1 and 2
(IKEv1 and IKEv2) PRF/PRF+ functions. (BZ#1213652)

All libreswan users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues and add these
enhancements.");
  script_tag(name:"affected", value:"libreswan on CentOS 7");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2015-June/021205.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS7")
{

  if ((res = isrpmvuln(pkg:"libreswan", rpm:"libreswan~3.12~10.1.el7_1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}

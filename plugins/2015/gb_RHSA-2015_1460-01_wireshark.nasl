###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for wireshark RHSA-2015:1460-01
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
  script_oid("1.3.6.1.4.1.25623.1.0.871408");
  script_version("$Revision: 12497 $");
  script_cve_id("CVE-2014-8710", "CVE-2014-8711", "CVE-2014-8712", "CVE-2014-8713",
                "CVE-2014-8714", "CVE-2015-0562", "CVE-2015-0564", "CVE-2015-2189",
                "CVE-2015-2191");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-07-23 06:26:28 +0200 (Thu, 23 Jul 2015)");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for wireshark RHSA-2015:1460-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'wireshark'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Wireshark, previously known as Ethereal, is a network protocol analyzer,
which is used to capture and browse the traffic running on a computer
network.

Several denial of service flaws were found in Wireshark. Wireshark could
crash or stop responding if it read a malformed packet off a network, or
opened a malicious dump file. (CVE-2014-8714, CVE-2014-8712, CVE-2014-8713,
CVE-2014-8711, CVE-2014-8710, CVE-2015-0562, CVE-2015-0564, CVE-2015-2189,
CVE-2015-2191)

This update also fixes the following bugs:

  * Previously, the Wireshark tool did not support Advanced Encryption
Standard Galois/Counter Mode (AES-GCM) cryptographic algorithm. As a
consequence, AES-GCM was not decrypted. Support for AES-GCM has been added
to Wireshark, and AES-GCM is now correctly decrypted. (BZ#1095065)

  * Previously, when installing the system using the kickstart method, a
dependency on the shadow-utils packages was missing from the wireshark
packages, which could cause the installation to fail with a 'bad scriptlet'
error message. With this update, shadow-utils are listed as required in the
wireshark packages spec file, and kickstart installation no longer fails.
(BZ#1121275)

  * Prior to this update, the Wireshark tool could not decode types of
elliptic curves in Datagram Transport Layer Security (DTLS) Client Hello.
Consequently, Wireshark incorrectly displayed elliptic curves types as
data. A patch has been applied to address this bug, and Wireshark now
decodes elliptic curves types properly. (BZ#1131203)

  * Previously, a dependency on the gtk2 packages was missing from the
wireshark packages. As a consequence, the Wireshark tool failed to start
under certain circumstances due to an unresolved symbol,
'gtk_combo_box_text_new_with_entry', which was added in gtk version 2.24.
With this update, a dependency on gtk2 has been added, and Wireshark now
always starts as expected. (BZ#1160388)

In addition, this update adds the following enhancements:

  * With this update, the Wireshark tool supports process substitution, which
feeds the output of a process (or processes) into the standard input of
another process using the ' (command_list)' syntax. When using process
substitution with large files as input, Wireshark failed to decode such
input. (BZ#1104210)

  * Wireshark has been enhanced to enable capturing packets with nanosecond
time stamp precision, which allows better analysis of recorded network
traffic. (BZ#1146578)

All wireshark users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues and add these
enhancements. All running instances of Wireshark must be restarted for the
update to take effect.");
  script_tag(name:"affected", value:"wireshark on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2015-July/msg00037.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~1.8.10~17.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wireshark-debuginfo", rpm:"wireshark-debuginfo~1.8.10~17.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wireshark-gnome", rpm:"wireshark-gnome~1.8.10~17.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}

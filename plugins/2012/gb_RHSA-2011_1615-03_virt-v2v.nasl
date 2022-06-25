###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for virt-v2v RHSA-2011:1615-03
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2011-December/msg00013.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870662");
  script_version("$Revision: 14114 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 12:48:52 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-07-09 10:44:33 +0530 (Mon, 09 Jul 2012)");
  script_cve_id("CVE-2011-1773");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_name("RedHat Update for virt-v2v RHSA-2011:1615-03");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'virt-v2v'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"virt-v2v on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"virt-v2v is a tool for converting and importing virtual machines to
  libvirt-managed KVM (Kernel-based Virtual Machine), or Red Hat Enterprise
  Virtualization.

  Using virt-v2v to convert a guest that has a password-protected VNC console
  to a KVM guest removed that password protection from the converted guest:
  after conversion, a password was not required to access the converted
  guest's VNC console. Now, converted guests will require the same VNC
  console password as the original guest. Note that when converting a guest
  to run on Red Hat Enterprise Virtualization, virt-v2v will display a
  warning that VNC passwords are not supported. (CVE-2011-1773)

  Note: The Red Hat Enterprise Linux 6.2 perl-Sys-Virt update must also be
  installed to correct CVE-2011-1773.

  Bug fixes:

  * When converting a guest virtual machine (VM), whose name contained
  certain characters, virt-v2v would create a converted guest with a
  corrupted name. Now, virt-v2v will not corrupt guest names. (BZ#665883)

  * There were numerous usability issues when running virt-v2v as a non-root
  user. This update makes it simpler to run virt-v2v as a non-root user.
  (BZ#671094)

  * virt-v2v failed to convert a Microsoft Windows guest with Windows
  Recovery Console installed in a separate partition. Now, virt-v2v will
  successfully convert a guest with Windows Recovery Console installed in a
  separate partition by ignoring that partition. (BZ#673066)

  * virt-v2v failed to convert a Red Hat Enterprise Linux guest which did not
  have the symlink '/boot/grub/menu.lst'. With this update, virt-v2v can
  select a grub configuration file from several places. (BZ#694364)

  * This update removes information about the usage of deprecated command
  line options in the virt-v2v man page. (BZ#694370)

  * virt-v2v would fail to correctly change the allocation policy, (sparse or
  preallocated) when converting a guest with QCOW2 image format. The error
  message 'Cannot import VM, The selected disk configuration is not
  supported' was displayed. With this update, allocation policy changes to a
  guest with QCOW2 storage will work correctly. (BZ#696089)

  * The options '--network' and '--bridge' can not be used
  in conjunction when converting a guest, but no error message was displayed.
  With this update, virt-v2v will now display an error message if the mutually
  exclusive '--network' and '--bridge' command line opti ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"virt-v2v", rpm:"virt-v2v~0.8.3~5.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}

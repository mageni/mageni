###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for ccid CESA-2013:0523 centos6
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2013-March/019294.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881636");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-03-12 09:59:00 +0530 (Tue, 12 Mar 2013)");
  script_cve_id("CVE-2010-4530");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_name("CentOS Update for ccid CESA-2013:0523 centos6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ccid'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  script_tag(name:"affected", value:"ccid on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"Chip/Smart Card Interface Devices (CCID) is a USB smart card reader
  standard followed by most modern smart card readers. The ccid package
  provides a Generic, USB-based CCID driver for readers, which follow this
  standard.

  An integer overflow, leading to an array index error, was found in the way
  the CCID driver processed a smart card's serial number. A local attacker
  could use this flaw to execute arbitrary code with the privileges of the
  user running the PC/SC Lite pcscd daemon (root, by default), by inserting a
  specially-crafted smart card. (CVE-2010-4530)

  This update also fixes the following bug:

  * Previously, CCID only recognized smart cards with 5V power supply. With
  this update, CCID also supports smart cards with different power supply.
  (BZ#808115)

  All users of ccid are advised to upgrade to this updated package, which
  contains backported patches to correct these issues.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"ccid", rpm:"ccid~1.3.9~6.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}

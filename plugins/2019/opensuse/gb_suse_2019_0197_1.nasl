# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.852304");
  script_version("$Revision: 13849 $");
  script_cve_id("CVE-2018-1000845");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-02-25 13:56:39 +0100 (Mon, 25 Feb 2019) $");
  script_tag(name:"creation_date", value:"2019-02-19 04:07:45 +0100 (Tue, 19 Feb 2019)");
  script_name("SuSE Update for avahi openSUSE-SU-2019:0197-1 (avahi)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-02/msg00034.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'avahi'
  package(s) announced via the openSUSE-SU-2019:0197_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for avahi fixes the following issues:

  Security issue fixed:

  - CVE-2018-1000845: Fixed DNS amplification and reflection to spoofed
  addresses (DOS) (bsc#1120281)

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-197=1");

  script_tag(name:"affected", value:"avahi on openSUSE Leap 15.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "openSUSELeap15.0")
{

  if ((res = isrpmvuln(pkg:"avahi", rpm:"avahi~0.6.32~lp150.4.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"avahi-autoipd", rpm:"avahi-autoipd~0.6.32~lp150.4.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"avahi-autoipd-debuginfo", rpm:"avahi-autoipd-debuginfo~0.6.32~lp150.4.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"avahi-compat-howl-devel", rpm:"avahi-compat-howl-devel~0.6.32~lp150.4.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"avahi-compat-mDNSResponder-devel", rpm:"avahi-compat-mDNSResponder-devel~0.6.32~lp150.4.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"avahi-debuginfo", rpm:"avahi-debuginfo~0.6.32~lp150.4.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"avahi-debugsource", rpm:"avahi-debugsource~0.6.32~lp150.4.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"avahi-glib2-debugsource", rpm:"avahi-glib2-debugsource~0.6.32~lp150.4.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"avahi-utils", rpm:"avahi-utils~0.6.32~lp150.4.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"avahi-utils-debuginfo", rpm:"avahi-utils-debuginfo~0.6.32~lp150.4.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"avahi-utils-gtk", rpm:"avahi-utils-gtk~0.6.32~lp150.4.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"avahi-utils-gtk-debuginfo", rpm:"avahi-utils-gtk-debuginfo~0.6.32~lp150.4.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-client3", rpm:"libavahi-client3~0.6.32~lp150.4.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-client3-debuginfo", rpm:"libavahi-client3-debuginfo~0.6.32~lp150.4.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-common3", rpm:"libavahi-common3~0.6.32~lp150.4.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-common3-debuginfo", rpm:"libavahi-common3-debuginfo~0.6.32~lp150.4.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-core7", rpm:"libavahi-core7~0.6.32~lp150.4.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-core7-debuginfo", rpm:"libavahi-core7-debuginfo~0.6.32~lp150.4.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-devel", rpm:"libavahi-devel~0.6.32~lp150.4.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-glib-devel", rpm:"libavahi-glib-devel~0.6.32~lp150.4.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-glib1", rpm:"libavahi-glib1~0.6.32~lp150.4.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-glib1-debuginfo", rpm:"libavahi-glib1-debuginfo~0.6.32~lp150.4.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-gobject-devel", rpm:"libavahi-gobject-devel~0.6.32~lp150.4.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-gobject0", rpm:"libavahi-gobject0~0.6.32~lp150.4.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-gobject0-debuginfo", rpm:"libavahi-gobject0-debuginfo~0.6.32~lp150.4.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-ui-gtk3-0", rpm:"libavahi-ui-gtk3-0~0.6.32~lp150.4.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-ui-gtk3-0-debuginfo", rpm:"libavahi-ui-gtk3-0-debuginfo~0.6.32~lp150.4.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-ui0", rpm:"libavahi-ui0~0.6.32~lp150.4.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-ui0-debuginfo", rpm:"libavahi-ui0-debuginfo~0.6.32~lp150.4.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libdns_sd", rpm:"libdns_sd~0.6.32~lp150.4.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libdns_sd-debuginfo", rpm:"libdns_sd-debuginfo~0.6.32~lp150.4.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libhowl0", rpm:"libhowl0~0.6.32~lp150.4.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libhowl0-debuginfo", rpm:"libhowl0-debuginfo~0.6.32~lp150.4.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-avahi", rpm:"python-avahi~0.6.32~lp150.4.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-avahi-gtk", rpm:"python-avahi-gtk~0.6.32~lp150.4.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"typelib-1_0-Avahi-0_6", rpm:"typelib-1_0-Avahi-0_6~0.6.32~lp150.4.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"avahi-lang", rpm:"avahi-lang~0.6.32~lp150.4.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"avahi-32bit-debuginfo", rpm:"avahi-32bit-debuginfo~0.6.32~lp150.4.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"avahi-mono", rpm:"avahi-mono~0.6.32~lp150.4.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"avahi-qt4-debugsource", rpm:"avahi-qt4-debugsource~0.6.32~lp150.4.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-client3-32bit", rpm:"libavahi-client3-32bit~0.6.32~lp150.4.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-client3-32bit-debuginfo", rpm:"libavahi-client3-32bit-debuginfo~0.6.32~lp150.4.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-common3-32bit", rpm:"libavahi-common3-32bit~0.6.32~lp150.4.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-common3-32bit-debuginfo", rpm:"libavahi-common3-32bit-debuginfo~0.6.32~lp150.4.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-glib1-32bit", rpm:"libavahi-glib1-32bit~0.6.32~lp150.4.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-glib1-32bit-debuginfo", rpm:"libavahi-glib1-32bit-debuginfo~0.6.32~lp150.4.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-qt4-1", rpm:"libavahi-qt4-1~0.6.32~lp150.4.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-qt4-1-debuginfo", rpm:"libavahi-qt4-1-debuginfo~0.6.32~lp150.4.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavahi-qt4-devel", rpm:"libavahi-qt4-devel~0.6.32~lp150.4.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libdns_sd-32bit", rpm:"libdns_sd-32bit~0.6.32~lp150.4.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libdns_sd-32bit-debuginfo", rpm:"libdns_sd-32bit-debuginfo~0.6.32~lp150.4.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}

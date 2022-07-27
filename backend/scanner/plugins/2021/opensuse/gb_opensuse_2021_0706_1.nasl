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
  script_oid("1.3.6.1.4.1.25623.1.0.853802");
  script_version("2021-05-25T12:16:58+0000");
  # TODO: No CVE assigned yet.
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-05-26 10:26:09 +0000 (Wed, 26 May 2021)");
  script_tag(name:"creation_date", value:"2021-05-12 03:03:13 +0000 (Wed, 12 May 2021)");
  script_name("openSUSE: Security Advisory for monitoring-plugins-smart (openSUSE-SU-2021:0706-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:0706-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/MAQBDZ7JPHIZTBDSB2BCFH7Y6AA2PXXF");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'monitoring-plugins-smart'
  package(s) announced via the openSUSE-SU-2021:0706-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for monitoring-plugins-smart fixes the following issues:

     monitoring-plugins-smart was updated to 6.9.1:

       This is a security-release (boo#1183057)
       + Fixes the regular expression for pseudo-devices under the /dev/bus/N
         path. from 6.9.0
       + Allows using PCI device paths as device name(s) (#64)
       + Introduce new optional parameter -l/--ssd-lifetime) which additionally
         checks SMART attribute 'Percent_Lifetime_Remain' (available on some
         SSD drives). (#66 #67) from 6.8.0
       + Allow skip self-assessment check (--skip-self-assessment)
       + Add Command_Timeout to default raw list from 6.7.1
       + Bugfix to make --warn work (issue #54) from 6.7.0
       + Added support for NVMe drives from 6.6.1
       + Fix &#x27 deprecation warning on regex with curly brackets&#x27  (6.6.1) from
         6.6.0
       + The feature was requested in #30 . This PR adds the possibility to use
         3ware, N and cciss, N drives in combination with the global -g parameter.
       + Furthermore this PR adjusts the output of the plugin when the -g is
         used in combination with hardware raid controllers. Instead of showing
         the logical device name (/dev/sda for example), the plugin will now
         show the controller with drive number from 6.5.0:
       + Add Reported_Uncorrect and Reallocated_Event_Count to default raw list.
       + As of 6.5 the following SMART attributes are by default checked and
         may result in alert when threshold (default 0 is reached):
         &#x27 Current_Pending_Sector, Reallocated_Sector_Ct, Program_Fail_Cnt_Total,
         Uncorrectable_Error_Cnt, Offline_Uncorrectable, Runtime_Bad_Block,
         Reported_Uncorrect, Reallocated_Event_Count&#x27

  - Update to version 6.4

  - Allow detection of more than 26 devices / issue #5 (rev 5.3)

  - Different ATA vs. SCSI lookup (rev 5.4)

  - Allow script to run outside of nagios plugins dir / wiki url update
         (rev 5.5)

  - Change syntax of -g parameter (regex is now awaited from input) (rev
         5.6)

  - Fix Use of uninitialized value $device (rev 5.7)

  - Allow multiple devices for interface type megaraid, e.g.
         'megaraid, [1-5]' (rev 5.8)

  - allow type 'auto' (rev 5.9)

  - Check selftest log for errors using new parameter -s (rev 5.10)

  - Add exclude list (-e) to ignore certain attributes (5.11)

  - Fix &#x27 Use of uninitialized value&#x27  warnings (5.11.1)

  - Add raw check list (-r) and warning thresholds (-w) (6.0)

  - Allow using pseudo b ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'monitoring-plugins-smart' package(s) on openSUSE Leap 15.2.");

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

  if(!isnull(res = isrpmvuln(pkg:"monitoring-plugins-smart", rpm:"monitoring-plugins-smart~6.9.1~lp152.4.3.1", rls:"openSUSELeap15.2"))) {
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
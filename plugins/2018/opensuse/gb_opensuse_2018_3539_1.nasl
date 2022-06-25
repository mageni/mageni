###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_3539_1.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# SuSE Update for wpa_supplicant openSUSE-SU-2018:3539-1 (wpa_supplicant)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.852104");
  script_version("$Revision: 12497 $");
  script_cve_id("CVE-2018-14526");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-10-28 06:04:13 +0100 (Sun, 28 Oct 2018)");
  script_name("SuSE Update for wpa_supplicant openSUSE-SU-2018:3539-1 (wpa_supplicant)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-10/msg00083.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wpa_supplicant'
  package(s) announced via the openSUSE-SU-2018:3539_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for wpa_supplicant provides the following fixes:

  This security issues was fixe:

  - CVE-2018-14526: Under certain conditions, the integrity of EAPOL-Key
  messages was not checked, leading to a decryption oracle. An attacker
  within range of the Access Point and client could have abused the
  vulnerability to recover sensitive information (bsc#1104205)

  These non-security issues were fixed:

  - Fix reading private key passwords from the configuration file.
  (bsc#1099835)

  - Enable PWD as EAP method. This allows for password-based authentication,
  which is easier to setup than most of the other methods, and is used by
  the Eduroam network. (bsc#1109209)

  - compile eapol_test binary to allow testing via radius proxy and server
  (note: this does not match CONFIG_EAPOL_TEST which sets -Werror and
  activates an assert call inside the code of wpa_supplicant)
  (bsc#1111873), (fate#326725)

  - Enabled timestamps in log file when being invoked by systemd service
  file (bsc#1080798).

  - Fixes the default file permissions of the debug log file to more sane
  values, i.e. it is no longer world-readable (bsc#1098854).

  - Open the debug log file with O_CLOEXEC, which will prevent file
  descriptor leaking to child processes (bsc#1098854).

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-1316=1");

  script_tag(name:"affected", value:"wpa_supplicant on openSUSE Leap 15.0.");

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

  if ((res = isrpmvuln(pkg:"wpa_supplicant", rpm:"wpa_supplicant~2.6~lp150.3.6.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wpa_supplicant-debuginfo", rpm:"wpa_supplicant-debuginfo~2.6~lp150.3.6.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wpa_supplicant-debugsource", rpm:"wpa_supplicant-debugsource~2.6~lp150.3.6.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wpa_supplicant-gui", rpm:"wpa_supplicant-gui~2.6~lp150.3.6.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wpa_supplicant-gui-debuginfo", rpm:"wpa_supplicant-gui-debuginfo~2.6~lp150.3.6.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}

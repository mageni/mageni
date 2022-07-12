###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_0544_1.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# SuSE Update for lame openSUSE-SU-2018:0544-1 (lame)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.851711");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-02-27 08:15:45 +0100 (Tue, 27 Feb 2018)");
  script_cve_id("CVE-2015-9100", "CVE-2015-9101", "CVE-2017-11720", "CVE-2017-13712", "CVE-2017-15019", "CVE-2017-9410", "CVE-2017-9411", "CVE-2017-9412", "CVE-2017-9869", "CVE-2017-9870", "CVE-2017-9871", "CVE-2017-9872");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for lame openSUSE-SU-2018:0544-1 (lame)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'lame'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for lame fixes the following issues:

  Lame was updated to version 3.100:

  * Improved detection of MPEG audio data in RIFF WAVE files. sf#3545112
  Invalid sampling detection

  * New switch --gain  decibel, range -20.0 to +12.0, a more convenient
  way to apply Gain adjustment in decibels, than the use of --scale
   factor .

  * Fix for sf#3558466 Bug in path handling

  * Fix for sf#3567844 problem with Tag genre

  * Fix for sf#3565659 no progress indication with pipe input

  * Fix for sf#3544957 scale (empty) silent encode without warning

  * Fix for sf#3580176 environment variable LAMEOPT doesn't work anymore

  * Fix for sf#3608583 input file name displayed with wrong character
  encoding (on windows console with CP_UTF8)

  * Fix dereference NULL and Buffer not NULL terminated issues.
  (CVE-2017-15019 bsc#1082317 CVE-2017-13712 bsc#1082399 CVE-2015-9100
  bsc#1082401)

  * Fix dereference of a null pointer possible in loop.

  * Make sure functions with SSE instructions maintain their own properly
  aligned stack. Thanks to Fabian Greffrath

  * Multiple Stack and Heap Corruptions from Malicious File.
  (CVE-2017-9872 bsc#1082391 CVE-2017-9871 bsc#1082392 CVE-2017-9870
  bsc#1082393 CVE-2017-9869 bsc#1082395 CVE-2017-9411 bsc#1082397
  CVE-2015-9101 bsc#1082400)

  * CVE-2017-11720: Fix a division by zero vulnerability. (bsc#1082311)

  * CVE-2017-9410: Fix fill_buffer_resample function in libmp3lame/util.c
  heap-based buffer over-read and ap (bsc#1082333)

  * CVE-2017-9411: Fix fill_buffer_resample function in libmp3lame/util.c
  invalid memory read and application crash (bsc#1082397)

  * CVE-2017-9412: FIx unpack_read_samples function in
  frontend/get_audio.c invalid memory read and application crash
  (bsc#1082340)

  * Fix clip detect scale suggestion unaware of scale input value

  * HIP decoder bug fixed: decoding mixed blocks of lower sample frequency
  Layer3 data resulted in internal buffer overflow.

  * Add lame_encode_buffer_interleaved_int()");
  script_tag(name:"affected", value:"lame on openSUSE Leap 42.3");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-02/msg00046.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.3");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSELeap42.3")
{

  if ((res = isrpmvuln(pkg:"lame", rpm:"lame~3.100~7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lame-debuginfo", rpm:"lame-debuginfo~3.100~7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lame-debugsource", rpm:"lame-debugsource~3.100~7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lame-doc", rpm:"lame-doc~3.100~7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lame-mp3rtp", rpm:"lame-mp3rtp~3.100~7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lame-mp3rtp-debuginfo", rpm:"lame-mp3rtp-debuginfo~3.100~7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmp3lame-devel", rpm:"libmp3lame-devel~3.100~7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmp3lame0", rpm:"libmp3lame0~3.100~7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmp3lame0-debuginfo", rpm:"libmp3lame0-debuginfo~3.100~7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmp3lame0-32bit", rpm:"libmp3lame0-32bit~3.100~7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmp3lame0-debuginfo-32bit", rpm:"libmp3lame0-debuginfo-32bit~3.100~7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}

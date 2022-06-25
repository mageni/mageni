# Copyright (C) 2018 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of their respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.852184");
  script_version("2020-04-02T11:36:28+0000");
  script_tag(name:"deprecated", value:TRUE);
  script_cve_id("CVE-2018-19968", "CVE-2018-19969", "CVE-2018-19970");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-04-03 10:09:42 +0000 (Fri, 03 Apr 2020)");
  script_tag(name:"creation_date", value:"2018-12-18 07:40:27 +0100 (Tue, 18 Dec 2018)");
  script_name("openSUSE: Security Advisory for phpMyAdmin (openSUSE-SU-2018:4124-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");

  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2018-12/msg00032.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'phpMyAdmin'
  package(s) announced via the openSUSE-SU-2018:4124-1 advisory.

  This NVT has been replaced by OID: 1.3.6.1.4.1.25623.1.0.814560");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for phpMyAdmin fixes security issues and bugs.

  Security issues addressed in the 4.8.4 release (bsc#1119245):

  - CVE-2018-19968: Local file inclusion through transformation feature

  - CVE-2018-19969: XSRF/CSRF vulnerability

  - CVE-2018-19970: XSS vulnerability in navigation tree

  This update also contains the following upstream bug fixes and
  improvements:

  - Ensure that database names with a dot ('.') are handled properly when
  DisableIS is true

  - Fix for message 'Error while copying database (pma__column_info)'

  - Move operation causes 'SELECT * FROM `undefined`' error

  - When logging with $cfg['AuthLog'] to syslog, successful login messages
  were not logged when $cfg['AuthLogSuccess'] was true

  - Multiple errors and regressions with Designer

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-1547=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-1547=1

  - openSUSE Backports SLE-15:

  zypper in -t patch openSUSE-2018-1547=1");

  script_tag(name:"affected", value:"phpMyAdmin on openSUSE Leap 42.3, openSUSE Leap 15.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

exit(66); ## This NVT is deprecated as addressed in OID:1.3.6.1.4.1.25623.1.0.814560

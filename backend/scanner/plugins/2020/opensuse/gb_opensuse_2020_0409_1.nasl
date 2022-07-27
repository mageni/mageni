# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.853088");
  script_version("2020-03-31T10:29:41+0000");
  script_cve_id("CVE-2019-2435");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2020-04-01 10:03:03 +0000 (Wed, 01 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-03-30 03:00:38 +0000 (Mon, 30 Mar 2020)");
  script_name("openSUSE: Security Advisory for python-mysql-connector-python (openSUSE-SU-2020:0409-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-03/msg00044.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-mysql-connector-python'
  package(s) announced via the openSUSE-SU-2020:0409-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python-mysql-connector-python fixes the following issues:

  python-mysql-connector-python was updated to 8.0.19 (boo#1122204 -
  CVE-2019-2435):

  - WL#13531: Remove xplugin namespace

  - WL#13372: DNS SRV support

  - WL#12738: Specify TLS ciphers to be used by a client or session

  - BUG#30270760: Fix reserved filed should have a length of 22

  - BUG#29417117: Close file in handle load data infile

  - WL#13330: Single C/Python (Win) MSI installer

  - WL#13335: Connectors should handle expired password sandbox without SET
  operations

  - WL#13194: Add support for Python 3.8

  - BUG#29909157: Table scans of floats causes memory leak with the C
  extension

  - BUG#25349794: Add read_default_file alias for option_files in connect()

  - WL#13155: Support new utf8mb4 bin collation

  - WL#12737: Add overlaps and not_overlaps as operator

  - WL#12735: Add README.rst and CONTRIBUTING.rst files

  - WL#12227: Indexing array fields

  - WL#12085: Support cursor prepared statements with C extension

  - BUG#29855733: Fix error during connection using charset and collation
  combination

  - BUG#29833590: Calling execute() should fetch active results

  - BUG#21072758: Support for connection attributes classic

  - WL#12864: Upgrade of Protobuf version to 3.6.1

  - WL#12863: Drop support for Django versions older than 1.11

  - WL#12489: Support new session reset functionality

  - WL#12488: Support for session-connect-attributes

  - WL#12297: Expose metadata about the source and binaries

  - WL#12225: Prepared statement support

  - BUG#29324966: Add missing username connection argument for driver
  compatibility

  - BUG#29278489: Fix wrong user and group for Solaris packages

  - BUG#29001628: Fix access by column label in Table.select()

  - BUG#28479054: Fix Python interpreter crash due to memory corruption

  - BUG#27897881: Empty LONG BLOB throws an IndexError

  - BUG#29260128: Disable load data local infile by default

  - WL#12607: Handling of Default Schema

  - WL#12493: Standardize count method

  - WL#12492: Be prepared for initial notice on connection

  - BUG#28646344: Remove expression parsing on values

  - BUG#28280321: Fix segmentation fault when using unicode characters in
  tables

  - BUG#27794178: Using use_pure=False should raise an error if cext is not
  available

  - BUG#27434751: Add a TLS/SSL option to verify server name

  - WL#12239: Add support for Python 3.7

  - WL#12226: Implement connect timeout

  - WL#11897: Implement connection pooling for xprotocol

  - BUG#28278352: C extension mysqlx Collection.add() leaks memory in
  sequential calls

  - B ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'python-mysql-connector-python' package(s) on openSUSE Leap 15.1.");

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

if(release == "openSUSELeap15.1") {

  if(!isnull(res = isrpmvuln(pkg:"python2-mysql-connector-python", rpm:"python2-mysql-connector-python~8.0.19~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-mysql-connector-python", rpm:"python3-mysql-connector-python~8.0.19~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
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